#ifndef CRYPTO12381_EXAMPLES_BBS04_BBS_HPP
#define CRYPTO12381_EXAMPLES_BBS04_BBS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::bbs_plus
{
    using namespace crypto12381;

    struct PublicParameters
    {
        serialized_field<G1, G2, G1> g1_g2_h0;
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

    // (A, x, r)
    struct Signature : serialized_field<G1, Zp, Zp>{};

    PublicParameters setup(size_t n, RandomEngine& random) noexcept;

    Keys key_gen(const PublicParameters& pp, RandomEngine& random) noexcept;

    Signature sign(const PublicParameters& pp, const PrivateKey& sk, std::span<const char> message, RandomEngine& random);

    bool verify(const PublicParameters& pp, const PublicKey& pk, std::span<const char> message, const Signature& signature);
}

#endif