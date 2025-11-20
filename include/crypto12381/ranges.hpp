#ifndef CRYPTO12381_RANGES_HPP
#define CRYPTO12381_RANGES_HPP

#include <type_traits>
#include <ranges>
#include <functional>

#include <miracl-core/core.h>

#include "general.hpp"

namespace crypto12381 
{
    template<std::ranges::view R>
    struct vector;

    template<typename R>
    vector(R&& r) -> vector<std::views::all_t<R>>;
}

namespace crypto12381::detail
{
    template<typename L, typename R>
    constexpr auto pow(L&& l, R&& r)
    noexcept(noexcept(std::forward<L>(l) ^ std::forward<R>(r)))
    requires requires{std::forward<L>(l) ^ std::forward<R>(r);}
    {
        return std::forward<L>(l) ^ std::forward<R>(r);
    }
    
    struct in_t
    {
        constexpr auto operator[](size_t n) const
        {
            return std::views::iota(0uz, n);
        }
    };

    struct i_t
    {
        static constexpr in_t in;
    };

    template<std::ranges::range RE, std::ranges::range RI>
    constexpr auto elements_in(RE&& elemens, RI&& indexes)
    {
        if constexpr(std::is_same_v<std::remove_cvref_t<RI>, decltype(std::views::iota(0uz, 1uz))>)
        {
            return std::forward<RE>(elemens) 
                | std::views::drop(*indexes.begin()) 
                | std::views::take(indexes.size());
        }
        else
        {
            static_assert(false, "Not implement yet");
        }
    }

    template<typename T>
    constexpr T&& base_unwrap(T&& t) noexcept
    {
        return (T&&)t;
    }

    template<typename T>
    constexpr auto&& base_unwrap(std::ranges::owning_view<T>& t) noexcept
    {
        return t.base();
    }

    template<typename T>
    constexpr auto&& base_unwrap(const std::ranges::owning_view<T>& t) noexcept
    {
        return t.base();
    }

    template<std::ranges::view V>
    class elementwise_view: public std::ranges::view_interface<elementwise_view<V>>
    {
    public:
        constexpr elementwise_view() requires std::default_initializable<V> = default;

        constexpr elementwise_view(V base) 
        noexcept(std::is_nothrow_move_constructible_v<V>)
        : base_(std::move(base))
        {}

        template<class Self>
        constexpr auto&& base(this Self&& self) noexcept
        {
            return detail::base_unwrap(std::forward_like<Self>(self.base_));
        }

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
        constexpr auto size(this Self&& self) requires std::ranges::sized_range<V>
        {
            return std::ranges::size(std::forward_like<Self>(self.base_));
        }

        template<class Self>
        constexpr auto data(this Self&& self)
            requires std::ranges::contiguous_range<std::remove_reference_t<decltype(self.base_)>>
        {
            return std::ranges::data(self.base_);
        }

        template<std::ranges::range RI, typename Self>
        constexpr auto operator[](this Self&& self, RI&& indexes)
        {
            return vector{
                detail::elements_in(std::forward<Self>(self).base(), std::forward<RI>(indexes))
            };
        }

        // template<std::ranges::range RI, typename Self>
        // constexpr auto operator|(this Self&& self, RI&& indexes)
        // {
        //     return detail::elements_in(std::forward<Self>(self).base(), std::forward<RI>(indexes));
        // }

        template<specified<elementwise_view> L, typename R>
        friend auto operator*(L&& l, R&& r)
        {
            return detail::elementwise_view{ std::views::zip_transform(
                std::multiplies<>{},
                std::forward<L>(l).base(), 
                std::forward<R>(r).base()
            )};
        }

        template<specified<elementwise_view> L, typename R>
        friend auto operator^(L&& l, R&& r)
        {
            return detail::elementwise_view{ std::views::zip_transform(
                std::bit_xor<>{},
                std::forward<L>(l).base(), 
                std::forward<R>(r).base()
            )};
        }

    private:
        V base_{};
    };

    template<typename R>
    elementwise_view(R&&) -> elementwise_view<std::views::all_t<R>>;

    template<typename T>
    concept elementwise_range = requires(std::remove_cvref_t<T>& t)
    {
        { []<typename U>(elementwise_view<U>& t){ return &t; }(t) } -> std::same_as<std::remove_cvref_t<T>*>;
    };

    template<std::ranges::range R>
    constexpr auto operator|(R&& r, i_t)
    {
        return elementwise_view{ std::forward<R>(r) };
    }
}

template <class V>
constexpr bool std::ranges::enable_borrowed_range<crypto12381::detail::elementwise_view<V>> = std::ranges::enable_borrowed_range<V>;

namespace crypto12381
{
    inline constexpr detail::i_t i{};

    template<std::ranges::view R>
    struct vector : public std::ranges::view_interface<vector<R>>
    {
    private:
        R base_{};
    public:
        using std::ranges::view_interface<vector<R>>::operator[];

        vector() requires std::default_initializable<R> = default;

        constexpr vector(R base) 
        noexcept(std::is_nothrow_move_constructible_v<R>)
        : base_(std::move(base))
        {}

        vector(vector&&)            = default;
        vector& operator=(vector&&) = default;

        template<class Self>
        constexpr auto&& base(this Self&& self) noexcept
        {
            return detail::base_unwrap(std::forward_like<Self>(self.base_));
        }

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

        template<class Self>
        constexpr auto data(this Self&& self)
            requires std::ranges::contiguous_range<std::remove_reference_t<decltype(self.base_)>>
        {
            return std::ranges::data(self.base_);
        }

        template<typename Self>
        auto operator[](this Self&& self, detail::i_t)
        {
            return detail::elementwise_view{ std::forward<Self>(self).base() };
        }

    
    };

    constexpr bool tt = std::ranges::view<vector<std::span<int>>>;

    constexpr bool tt2 = std::ranges::view<std::ranges::owning_view<std::span<int>>>;
}

template <class R>
constexpr bool std::ranges::enable_borrowed_range<crypto12381::vector<R>> = std::ranges::enable_borrowed_range<R>;

#endif