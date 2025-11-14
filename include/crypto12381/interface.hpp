#ifndef CRYPTO12381_INTERFACE_HPP
#define CRYPTO12381_INTERFACE_HPP

#include <array>
#include <span>
#include "random.hpp"

namespace crypto12381 
{
    namespace detail 
    {
        struct Zp_t{};
        struct G1_t{};
        struct G2_t{};
    }

    inline constexpr detail::Zp_t Zp{};
    inline constexpr detail::G1_t G1{};
    inline constexpr detail::G2_t G2{};

    template<auto Set>
    inline constexpr size_t serialized_size = serialized_size<Set.base> * Set.exponent;

    template<>
    inline constexpr size_t serialized_size<Zp> = 48uz;
    template<>
    inline constexpr size_t serialized_size<G1> = 48uz + 1uz;
    template<>
    inline constexpr size_t serialized_size<G2> = 2uz * 48uz + 1uz;

    template<auto...Set>
    using serialized_field = std::array<char, (0uz + ... + serialized_size<Set>)>;

    template<auto...Set>
    using serialized_view = std::span<const char, (0uz + ... + serialized_size<Set>)>;
}

namespace crypto12381::detail 
{
    template<typename Set>
    struct CartesianPower
    {
        Set base;
        size_t exponent;
    };

    constexpr auto operator^(Zp_t, size_t exponent) noexcept
    {
        return CartesianPower{ Zp, exponent };
    }
    constexpr auto operator^(G1_t, size_t exponent) noexcept
    {
        return CartesianPower{ G1, exponent };
    }
    constexpr auto operator^(G2_t, size_t exponent) noexcept
    {
        return CartesianPower{ G2, exponent };
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