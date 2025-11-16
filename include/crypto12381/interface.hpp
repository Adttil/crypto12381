#ifndef CRYPTO12381_INTERFACE_HPP
#define CRYPTO12381_INTERFACE_HPP

#include <array>
#include <span>
#include "random.hpp"

namespace crypto12381 
{
    namespace detail::sets
    {
        struct Zp_t
        {
            consteval size_t serialized_size() const noexcept
            {
                return 48uz;
            }
        };
        struct G1_t
        {
            consteval size_t serialized_size() const noexcept
            {
                return 48uz + 1uz;
            }
        };
        struct G2_t
        {
            consteval size_t serialized_size() const noexcept
            {
                return 2uz * 48uz + 1uz;
            }
        };
        struct GT_t
        {
            consteval size_t serialized_size() const noexcept
            {
                return 12uz * 48uz;
            }
        };
    }

    inline constexpr detail::sets::Zp_t Zp{};
    inline constexpr detail::sets::G1_t G1{};
    inline constexpr detail::sets::G2_t G2{};
    inline constexpr detail::sets::GT_t GT{};

    template<auto Set>
    inline constexpr size_t serialized_size = Set.serialized_size();

    template<auto...Set>
    using serialized_field = std::array<char, (0uz + ... + serialized_size<Set>)>;

    template<auto...Set>
    using serialized_view = std::span<const char, (0uz + ... + serialized_size<Set>)>;
}

namespace crypto12381::detail::sets
{
    template<typename Set>
    struct CartesianPower
    {
        Set base;
        size_t exponent;

        constexpr size_t serialized_size() const noexcept
        {
            return base.serialized_size() * exponent;
        }
    };

    template<typename T>
    constexpr auto operator^(T t, size_t exponent) noexcept
    {
        return CartesianPower{ t, exponent };
    }

    template<typename Set>
    constexpr auto operator^(CartesianPower<Set> power, size_t exponent) noexcept
    {
        return CartesianPower{ power.base, power.exponent * exponent };
    }

    template<typename L, typename R>
    constexpr auto pow(L&& l, R&& r)
    noexcept(noexcept(std::forward<L>(l) ^ std::forward<R>(r)))
    requires requires{std::forward<L>(l) ^ std::forward<R>(r);}
    {
        return std::forward<L>(l) ^ std::forward<R>(r);
    }
}

#endif