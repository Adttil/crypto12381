#ifndef CRYPTO12381_SET_HPP
#define CRYPTO12381_SET_HPP

#include <print>

#include <tuple>
#include <type_traits>
#include <ranges>

#include <miracl-core/core.h>

#include "general.hpp"
#include "random.hpp"
#include "constant.hpp"
#include "interface.hpp"

namespace crypto12381::detail
{
    template<typename L, typename R>
    constexpr auto pow(L&& l, R&& r)
    noexcept(noexcept(std::forward<L>(l) ^ std::forward<R>(r)))
    requires requires{std::forward<L>(l) ^ std::forward<R>(r);}
    {
        return std::forward<L>(l) ^ std::forward<R>(r);
    }

    template<typename F>
    struct indexer_fn : F
    {
        template<specified<indexer_fn> L, typename R>
        friend auto operator*(L&& l, R&& r)
        {
            return detail::indexer_fn{
                [l_r = std::tuple<L, R>{ std::forward<L>(l), std::forward<R>(r) }]<typename C>(this C&& sself, size_t i)
                {
                    auto&&[l, r] = std::forward_like<C>(l_r);
                    return l(i) * r(i);
                }
            };
        }

        template<specified<indexer_fn> L, typename R>
        friend auto operator^(L&& l, R&& r)
        {
            return detail::indexer_fn{
                [l_r = std::tuple<L, R>{ std::forward<L>(l), std::forward<R>(r) }]<typename C>(this C&& sself, size_t i)
                {
                    auto&&[l, r] = std::forward_like<C>(l_r);
                    return l(i) ^ r(i);
                }
            };
        }
    };

    struct i_t{};
}

namespace crypto12381
{
    template<std::ranges::view R>
    struct vector : public std::ranges::view_interface<vector<R>>
    {
    public:
        using std::ranges::view_interface<vector<R>>::operator[];

        vector() requires std::default_initializable<R> = default;

        constexpr vector(R base) 
        noexcept(std::is_nothrow_move_constructible_v<R>)
        : base_(std::move(base))
        {}

        template<class Self>
        constexpr auto begin(this Self&& self)
        {
            return std::ranges::begin(std::forward_like<Self>(self.base_));
        }

        template<class Self>
        constexpr auto end(this Self&& self)
        {
            return std::ranges::end(std::forward_like<Self>(self.base_));
        }


        template<class Self>
        constexpr auto size(this Self&& self) requires std::ranges::sized_range<R>
        {
            return std::ranges::size(std::forward_like<Self>(self.base_));
        }

        template<typename Self>
        auto operator[](this Self&& self, detail::i_t)
        {
            return detail::indexer_fn{
                [r = std::tuple<Self>(std::forward<Self>(self))]<typename Closure>(this Closure&&, size_t i)
                {
                    return std::forward_like<Closure>(std::get<0>(r))[i];
                }
            };
        }

    private:
        R base_;
    };

    template<typename R>
    vector(R&& r) -> vector<std::views::all_t<R>>;
}

template <class R>
constexpr bool std::ranges::enable_borrowed_range<crypto12381::vector<R>> = std::ranges::enable_borrowed_range<R>;

namespace crypto12381
{
    template<typename T>
    concept selectable = requires(const T& t, RandomEngine& random) 
    {
        select_in(constant<std::remove_cvref_t<T>{}>, random);
        // { contains(
        //     constant<std::remove_cvref_t<T>{}>, 
        //     std::type_identity<std::remove_cvref_t<decltype(select_in(constant<std::remove_cvref_t<T>{}>, random))>>{}
        // ) } -> std::same_as<bool>;
    };

    template<typename T>
    concept parseable = requires(serialized_view<std::remove_cvref_t<T>{}> bytes) 
    {
        parse(constant<std::remove_cvref_t<T>{}>, bytes);
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

    template<auto Set>
    inline constexpr detail::select_in_fn<Set> select_in{};

    template<auto...Set>
    inline constexpr detail::parse_fn<Set...> parse{};

    template<auto Set>
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

        template<typename T>
        constexpr auto operator()(T&& t) const
        {
            if constexpr(std::is_trivially_copyable_v<std::remove_cvref_t<T>> && sizeof(t) == bytes_size)
            {
                return (*this)(std::span{ reinterpret_cast<const char(&)[sizeof(t)]>(t) });
            }
            else if constexpr(std::convertible_to<T&, std::span<const char, bytes_size>>)
            {
                const auto bytes = (std::span<const char, bytes_size>)t;
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
            else if constexpr(std::ranges::range<T> && requires(std::ranges::range_value_t<T> e){ (*this)(e); })
            {
                return vector{ std::forward<T>(t) | std::views::transform(crypto12381::parse<Set...>) };
            }
            else
            {
                static_assert(false, "can not parse");
            }
        }

        template<typename T>
        constexpr auto operator()(std::reference_wrapper<T> t) const
        {
            return (*this)(t.get());
        }

        // constexpr auto operator()(std::span<const char, bytes_size> bytes) const
        // {
        //     if constexpr(sizeof...(Set) == 1uz)
        //     {
        //         return (..., parse(constant<Set>, bytes));
        //     }
        //     else return [&]<size_t...I>(std::index_sequence<I...>){
        //         using tpl = std::tuple<constant_t<Set>...>;
        //         return std::tuple{
        //             parse(std::tuple_element_t<I, tpl>{}, (bytes.template subspan<offsets[I], sizes[I]>()))...
        //         };

        //         // clang bug
        //         // return std::tuple{
        //         //     parse(constant_t<Set>{}, (bytes.template subspan<offsets[I], sizes[I]>()))...
        //         // };
        //     }(std::make_index_sequence<sizeof...(Set)>{});
        // }

        // template<typename T> requires (std::is_trivially_copyable_v<T>)
        // constexpr auto operator()(const T& t) const
        // {
        //     return (*this)(std::span{ reinterpret_cast<const char(&)[sizeof(T)]>(t) });
        // }

        // template<std::ranges::range R> requires (sizeof...(Set) == 1uz)
        // constexpr auto operator()(R&& r) const
        // requires requires(std::ranges::range_value_t<R> e){ (*this)(e); }
        // {
        //     return vector{ std::forward<R>(r) | std::views::transform(crypto12381::parse<Set...>) };
        // }
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
        else if constexpr(element_of<T, GT>)
        {
            return GT;
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

        template<typename Self>
        constexpr std::array<char, byte_count> to(this Self&& self) noexcept
        {
            std::array<char, byte_count> result;
            std::forward<Self>(self).to(result);
            return result;
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
    public:
        static constexpr const int hash_size = 64;

        hash_state() noexcept
        {
            core::SHA3_init(&state_, hash_size);
        }
        
        template<typename T>
        constexpr hash_state&& operator|(const T& t)&& noexcept
        {
            process(t);
            return std::move(*this);
        }
        
        void to(std::span<char, hash_size> bytes)&& noexcept
        {
            core::SHA3_hash(&state_, bytes.data());
        }

        auto to()&& noexcept
        {
            std::array<char, hash_size> buffer;
            std::move(*this).to(buffer);
            return buffer;
        }

        template<typename Set>
        constexpr auto to(Set) && noexcept
        requires requires{hash_to(std::move(*this), Set{});}
        {
            return hash_to(std::move(*this), Set{});
        }

    private:
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
            if constexpr(not std::same_as<decltype(group_of<T>()), void>)
            {
                serialized_field<group_of<T>()> buffer = serialize(t);
                process(buffer);
            }
            else if constexpr(std::is_trivially_copyable_v<T>)
            {
                process(std::span{ reinterpret_cast<const char(&)[sizeof(T)]>(t) });
            }
            else if constexpr(std::ranges::range<const T&>)
            {
                for(const auto& e : t)
                {
                    process(e);
                }
            }
            else
            {
                static_assert(false, "can not hash T");
            }
        }

        core::sha3 state_;
    };

    struct hash_fn
    {
        template<typename...Args>
        constexpr hash_state operator()(Args&&...args) const noexcept
        {
            return (hash_state{} | ... | std::forward<Args>(args));
        }

        template<typename T, typename Self>
        constexpr hash_state operator|(const T& t) const noexcept
        {
            return hash_state{} | t;
        }
    };

    void sum();

    struct sum_fn
    {
        template<std::ranges::range R>
        constexpr auto operator()(R&& r) const
        {
            return sum(std::type_identity<std::remove_cvref_t<std::ranges::range_value_t<R>>>{}, std::forward<R>(r));
        }

        template<typename F>
        constexpr auto operator()(size_t n, F&& f) const
        {
            return (*this)(std::views::iota(0uz, n) | std::views::transform(std::forward<F>(f)));
        }
    };

    void product() = delete;

    struct product_fn
    {
        template<std::ranges::range R>
        constexpr auto operator()(R&& r) const
        {
            return product(std::type_identity<std::remove_cvref_t<std::ranges::range_value_t<R>>>{}, std::forward<R>(r));
        }

        template<typename F>
        constexpr auto operator()(size_t n, F&& f) const
        {
            return (*this)(std::views::iota(0uz, n) | std::views::transform(std::forward<F>(f)));
        }
    };    
}

namespace crypto12381
{
    inline constexpr detail::hash_fn hash{};
    
    inline constexpr detail::sum_fn sum{};

    inline constexpr detail::product_fn product{};

    inline constexpr detail::i_t i{};

    inline constexpr auto Σ = sum;

    inline constexpr auto Π = product;
}

namespace crypto12381::detail::sets 
{
    template<cartesian_power Set>
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

    // template<cartesian_power Set, typename T>
    // consteval bool contains(constant_t<Set>, std::type_identity<T>) noexcept
    // {
    //     if constexpr(Set.exponent == 1)
    //     {
    //         return contains(constant<Set.base>, std::type_identity<T>{});
    //     }
    //     else return [&]<size_t...I>(std::index_sequence<I...>){
    //         return (true && ... && contains((I - I, constant<Set.base>), std::type_identity<std::tuple_element_t<I, T>>{}));
    //     }(std::make_index_sequence<Set.exponent>{});
    // }

    template<cartesian_power Set>
    constexpr auto parse(constant_t<Set>, serialized_view<Set> bytes)
    {
        if constexpr(Set.exponent == 1)
        {
            return crypto12381::parse<Set.base>(bytes);
        }
        else return [&]<size_t...I>(std::index_sequence<I...>){
            return crypto12381::parse<cartesian_power{ Set.base, 1uz + (I - I) }...>(bytes);
        }(std::make_index_sequence<Set.exponent>{});
    }

    template<typename L, typename R>
    struct cartesian_product
    {
        L l;
        R r;

        constexpr size_t serialized_size() const noexcept
        {
            return l.serialized_size() + r.serialized_size();
        }
    };

    template<typename L, typename R>
    constexpr auto operator*(L l, R r) noexcept
    {
        return cartesian_product{ l, r };
    }

    template<typename L, typename R>
    constexpr auto operator|(L l, R r) noexcept
    {
        return cartesian_product{ l, r };
    }

    template<cartesian_product Set>
    constexpr auto parse(constant_t<Set>, serialized_view<Set> bytes)
    {
        return std::tuple_cat(
            std::tuple{ crypto12381::parse<Set.l>(bytes.template subspan<0uz, serialized_size<Set.l>>()) },
            std::tuple{ crypto12381::parse<Set.r>(bytes.template subspan<serialized_size<Set.l>, serialized_size<Set.r>>()) }
        );
    }
}

#endif