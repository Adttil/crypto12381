#ifndef CRYPTO12381_GENERAL_HPP
#define CRYPTO12381_GENERAL_HPP

#include <concepts>
#include <type_traits>

namespace crypto12381::detail
{
    template<typename T, typename U>
    concept specified = std::same_as<std::remove_cvref_t<T>, U>;
}

#endif