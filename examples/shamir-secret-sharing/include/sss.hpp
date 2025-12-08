#ifndef CRYPTO12381_EXAMPLES_SSS_SSS_HPP
#define CRYPTO12381_EXAMPLES_SSS_SSS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::sss
{
    using namespace crypto12381;

    std::vector<serialized_field<Zp>> share(size_t t, size_t n, serialized_field<Zp> secret, RandomEngine& random) noexcept;

    serialized_field<Zp> reconstruct(std::span<const size_t> indexes, std::span<const serialized_field<Zp>> share) noexcept;
}

#endif