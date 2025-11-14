#ifndef CRYPTO12381_SET_HPP
#define CRYPTO12381_SET_HPP

#include <tuple>

#include <miracl-core/core.h>

#include "random.hpp"
#include "constant.hpp"
#include "interface.hpp"

namespace crypto12381
{
    template<typename T>
    concept set = requires(RandomEngine& random) 
    {
        select_in(constant<std::remove_cvref_t<T>{}>, random);
        { contains(
            constant<std::remove_cvref_t<T>{}>, 
            std::type_identity<std::remove_cvref_t<decltype(select_in(constant<std::remove_cvref_t<T>{}>, random))>>{}
        ) } -> std::same_as<bool>;
    };

    template<typename T, auto Set>
    concept element_of = (contains(constant<Set>, std::type_identity<std::remove_cvref_t<T>>{}));

    namespace detail 
    {
        template<auto Set>
        struct select_in_fn;

        template<auto...Set>
        struct parse_fn;

        template<auto Set>
        struct encode_to_fn;
    }

    template<set auto Set>
    inline constexpr detail::select_in_fn<Set> select_in{};

    template<set auto...Set>
    inline constexpr detail::parse_fn<Set...> parse{};

    template<set auto Set>
    inline constexpr detail::encode_to_fn<Set> encode_to{};
}

namespace crypto12381::detail
{
    void select_in();

    void parse();

    void serialize_to();

    void encode_to();

    void hash_to();

    template<auto Set>
    struct select_in_fn
    {
        constexpr auto operator()(RandomEngine& random) const noexcept
        {
            return select_in(std::integral_constant<decltype(Set), Set>{}, random);
        }
        
        friend constexpr auto operator-(RandomEngine& random, select_in_fn) noexcept
        {
            return select_in_fn{}(random);
        }
    };

    template<auto...Set>
    struct parse_fn
    {
        static constexpr size_t bytes_size = (0uz + ... + serialized_size<Set>);

        static constexpr auto sizes = std::array{ serialized_size<Set>... };
        static constexpr auto offsets = []()
        {
            auto result = std::array<size_t, sizeof...(Set)>{};
            for(size_t i = 1; i < sizeof...(Set); ++i)
            {
                result[i] = result[i - 1] + sizes[i - 1];
            }
            return result;
        }();

        constexpr auto operator()(std::span<const char, bytes_size> bytes) const
        {
            if constexpr(sizeof...(Set) == 1uz)
            {
                return (..., parse(constant<Set>, bytes));
            }
            else return [&]<size_t...I>(std::index_sequence<I...>){
                using tpl = std::tuple<constant_t<Set>...>;
                return std::tuple{
                    parse(std::tuple_element_t<I, tpl>{}, (bytes.template subspan<offsets[I], sizes[I]>()))...
                };

                // clang bug
                // return std::tuple{
                //     parse(constant_t<Set>{}, (bytes.template subspan<offsets[I], sizes[I]>()))...
                // };
            }(std::make_index_sequence<sizeof...(Set)>{});
        }

        template<typename T> requires (std::is_trivially_copyable_v<T>)
        constexpr auto operator()(const T& t) const
        {
            return (*this)(std::span{ reinterpret_cast<const char(&)[sizeof(T)]>(t) });
        }
    };

    template<auto Set>
    struct encode_to_fn
    {
        constexpr auto operator()(std::span<const char> message) const noexcept
        {
            return encode_to(constant<Set>, message);
        };
    };

    template<typename T>
    consteval auto group_of()
    {
        if constexpr(element_of<T, Zp>)
        {
            return Zp;
        }
        else if constexpr(element_of<T, G1>)
        {
            return G1;
        }
        else if constexpr(element_of<T, G2>)
        {
            return G2;
        }
    }

    template<typename...Args>
    struct serialize_pack
    {
        std::tuple<Args...> args;

        static constexpr size_t byte_count = (0uz + ... + serialized_size<group_of<Args>()>);
        static constexpr auto sizes = std::array{ serialized_size<group_of<Args>()>... };
        static constexpr auto offsets = []()
        {
            auto result = std::array<size_t, sizeof...(Args)>{};
            for(size_t i = 1; i < sizeof...(Args); ++i)
            {
                result[i] = result[i - 1] + sizes[i - 1];
            }
            return result;
        }();

        template<typename Self>
        constexpr void to(this Self&& self, std::span<char, byte_count> bytes) noexcept
        {
            [&]<size_t...I>(std::index_sequence<I...>){
                (..., serialize_to(
                    bytes.template subspan<offsets[I], sizes[I]>(), 
                    std::get<I>(std::forward_like<Self>(self.args))
                ));
            }(std::make_index_sequence<sizeof...(Args)>{});
        }

        template<typename T, typename Self>
        requires (std::is_trivially_copyable_v<T> && sizeof(T) == byte_count)
        constexpr void to(this Self&& self, T& t) noexcept
        {
            return std::forward<Self>(self).to(std::span{ reinterpret_cast<char(&)[sizeof(T)]>(t) });
        }

        template<std::default_initializable T, typename Self>
        requires (std::is_trivially_copyable_v<T> && sizeof(T) == byte_count)
        constexpr T to(this Self&& self) noexcept
        {
            T t;
            std::forward<Self>(self).to(t);
            return t;
        }

        template<std::default_initializable T, typename Self>
        requires (std::is_trivially_copyable_v<T> && sizeof(T) == byte_count)
        constexpr operator T(this Self&& self) noexcept
        {
            return std::forward<Self>(self).template to<T>();
        }
    };

    constexpr auto operator^(const set auto& base, size_t exponent) noexcept
    {
        return CartesianPower{ base, exponent };
    }

    template<CartesianPower Set>
    constexpr auto select_in(constant_t<Set>, RandomEngine& random) noexcept
    {
        if constexpr(Set.exponent == 1)
        {
            return select_in(constant<Set.base>, random);
        }
        else return [&]<size_t...I>(std::index_sequence<I...>){
            return std::tuple{
                random-crypto12381::select_in<Set.base^(1 + (I - I))>...
            };
        }(std::make_index_sequence<Set.exponent>{});
    }

    template<CartesianPower Set, typename T>
    consteval bool contains(constant_t<Set>, std::type_identity<T>) noexcept
    {
        if constexpr(Set.exponent == 1)
        {
            return contains(constant<Set.base>, std::type_identity<T>{});
        }
        else return [&]<size_t...I>(std::index_sequence<I...>){
            return (true && ... && contains((I - I, constant<Set.base>), std::type_identity<std::tuple_element_t<I, T>>{}));
        }(std::make_index_sequence<Set.exponent>{});
    }

    template<CartesianPower Set>
    constexpr auto parse(constant_t<Set>, std::span<const char, serialized_size<Set.base> * Set.exponent> bytes)
    {
        if constexpr(Set.exponent == 1)
        {
            return crypto12381::parse<Set.base>(bytes);
        }
        else return [&]<size_t...I>(std::index_sequence<I...>){
            return crypto12381::parse<CartesianPower{ Set.base, 1uz + (I - I) }...>(bytes);
        }(std::make_index_sequence<Set.exponent>{});
    }
}

namespace crypto12381
{
    namespace detail 
    {
        struct serialize_fn
        {
            template<typename...Args> 
            constexpr serialize_pack<Args...> operator()(Args&&...args) const
            {
                return {{ std::forward<Args>(args)... }};
            }
        };
    }

    inline constexpr detail::serialize_fn serialize{};
}

namespace crypto12381::detail 
{
    class hash_state
    {
    friend class hash_fn;
    public:
        static constexpr const int hash_size = 64;
        hash_state() noexcept
        {
            core::SHA3_init(&state_, hash_size);
        }
        
        template<size_t N>
        void process(std::span<const char, N> bytes) noexcept
        {
            for(const auto& byte : bytes)
            {
                core::SHA3_process(&state_, byte);
            }
        }

        template<typename T>
        void process(const T& t) noexcept
        {
            if constexpr(std::is_trivially_copyable_v<T>)
            {
                process(std::span{ reinterpret_cast<const char(&)[sizeof(T)]>(t) });
            }
            else
            {
                serialized_field<group_of<T>()> buffer = serialize(t);
                process(buffer);
            }
        }

        template<typename T, typename Self>
        constexpr Self&& operator|(this Self&& self, const T& t) noexcept
        {
            self.process(t);
            return std::forward<Self>(self);
        }
        
        void to(std::span<char, hash_size> bytes)&& noexcept
        {
            core::SHA3_hash(&state_, bytes.data());
        }

        template<set Set>
        constexpr auto to(Set) && noexcept
        {
            return hash_to(std::move(*this), Set{});
        }

    private:
        

        core::sha3 state_;
    };

    struct hash_fn
    {
        template<typename...Args>
        constexpr hash_state operator()(Args&&...args) const noexcept
        {
            hash_state state;
            return (state | ... | args);
        }

        template<typename T, typename Self>
        constexpr hash_state operator|(const T& t) const noexcept
        {
            return hash_state{} | t;
        }
    };
}

namespace crypto12381
{
    inline constexpr detail::hash_fn hash{};
}

#endif