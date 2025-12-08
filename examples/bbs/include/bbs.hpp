#ifndef CRYPTO12381_EXAMPLES_BBS_BBS_HPP
#define CRYPTO12381_EXAMPLES_BBS_BBS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::bbs
{
    using namespace crypto12381;

    struct PublicParameters
    {
        serialized_field<G1, G2> g1_g2;
        std::vector<serialized_field<G1>> h;
    };

    // (w)
    struct PublicKey : serialized_field<G2>{};

    // (γ)
    struct PrivateKey : serialized_field<Zp>{};

    struct Keys
    {
        PublicKey  pk;
        PrivateKey sk;
    };

    // (A, x)
    struct Signature : serialized_field<G1, Zp>{};

    PublicParameters setup(size_t n, RandomEngine& random) noexcept;

    Keys key_gen(const PublicParameters& pp, RandomEngine& random) noexcept;

    std::vector<serialized_field<Zp>> encode_message(std::span<const char> original_message) noexcept;

    Signature sign(const PublicParameters& pp, const PrivateKey& sk, std::span<const serialized_field<Zp>> message, RandomEngine& random);

    bool verify(const PublicParameters& pp, const PublicKey& pk, std::span<const serialized_field<Zp>> message, const Signature& signature);
}

#endif