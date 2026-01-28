#ifndef CRYPTO12381_EXAMPLES_AC_BBS_HPP
#define CRYPTO12381_EXAMPLES_AC_BBS_HPP

#include <vector>

#include <crypto12381/interface.hpp>

namespace crypto12381::ac_bbs 
{
    using namespace crypto12381;

    //x
    struct PrivateKey : serialized_field<Zp>{};

    struct PublicKey
    {
        //(g, tilde_g, tilde_X)
        serialized_field<G1, G2^2> fixed_part;
        std::vector<serialized_field<G1>> Y;
    };

    struct Keys
    {
        PrivateKey sk;
        PublicKey pk;
    };
    
    //(A, w)
    struct Signature : serialized_field<G1, Zp>{};
    
    struct PresInfo
    {
        //(A_, B_, U, s, t)
        serialized_field<G1^3, Zp^2> fixed_part;
        std::vector<serialized_field<Zp>> u;
    };

    Keys keygen(size_t n, RandomEngine& random);

    std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random);

    Signature issue(const Keys& keys, std::span<serialized_field<Zp>> attr, RandomEngine& random);

    PresInfo pres(std::span<const char> m, std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk, RandomEngine& random);

    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, const PresInfo& pres, const PublicKey& pk);
}

#endif