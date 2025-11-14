#ifndef BLS12381_CONSTANT_HPP
#define BLS12381_CONSTANT_HPP

#include <type_traits>

namespace crypto12381 
{
    template<auto Value>
    using constant_t = std::integral_constant<decltype(Value), Value>;
    // {
    //     static constexpr auto value = Value;
    // };

    template<auto Value>
    inline constexpr constant_t<Value> constant{};
}

#endif