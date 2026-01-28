#ifndef CRYPTO12381_EXAMPLES_AC_RBBS_HPP
#define CRYPTO12381_EXAMPLES_AC_RBBS_HPP

#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::ac_rbbs 
{
    using namespace crypto12381;

    struct PrivateKey : serialized_field<Zp^2>{};

    struct PublicKey
    {
        //(g, tilde_g, tilde_X)
        serialized_field<G1, G2^2> fixed_part;
        std::vector<serialized_field<G1>> Y;
        std::vector<serialized_field<G2>> tilde_Y;
    };

    struct Keys
    {
        PrivateKey sk;
        PublicKey pk;
    };
    
    struct Signature : serialized_field<G1, Zp>{};
    
    //(C_I, C_J, B, D)
    struct RedactCache : serialized_field<G1^4>{};
    
    //(A_, B_, C_J, D_, U, s, t)
    struct PresInfo : serialized_field<G1^5, Zp^2>{};

    Keys keygen(size_t n, RandomEngine& random);

    std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random);

    Signature issue(const Keys& keys, std::span<serialized_field<Zp>> attr, RandomEngine& random);

    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk);

    PresInfo pres(std::span<const char> m, const Signature& sig, const RedactCache& redact_cache, RandomEngine& random);

    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, const PresInfo& pres, const PublicKey& pk);
}

#endif