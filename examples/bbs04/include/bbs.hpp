#ifndef CRYPTO12381_EXAMPLES_BBS04_BBS_HPP
#define CRYPTO12381_EXAMPLES_BBS04_BBS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::bbs04
{
    using namespace crypto12381;

    // (g1, g2, h, u, v, w)
    struct GroupPublicKey : serialized_field<G1, G2, G1^3, G2>{};

    // (ξ1, ξ2)
    struct GroupManagerPrivateKey : serialized_field<Zp^2>{};

    // (A, x)
    struct GroupMemberPrivateKey : serialized_field<G1, Zp>{};

    struct Keys
    {
        GroupPublicKey gpk;
        GroupManagerPrivateKey gmsk;
        std::vector<GroupMemberPrivateKey> gsk;
    };

    // (t1, t2, t3, c, sα, sβ, sx, sδ1, sδ2)
    struct Signature : serialized_field<G1^3, Zp^6>{};

    Keys key_gen(size_t n, RandomEngine& random) noexcept;

    Signature sign(const GroupPublicKey& gpk, const GroupMemberPrivateKey& gsk, std::span<const char> message, RandomEngine& random) noexcept;

    bool verify(const GroupPublicKey& gpk, std::span<const char> message, const Signature& signature) noexcept;

    // return the "a" in the member's gsk. (gsk.a)
    // Must verify the signature before call this
    serialized_field<G1> open(const GroupManagerPrivateKey& gmsk, const Signature& signature) noexcept;
}

#endif