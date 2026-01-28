#ifndef CRYPTO12381_EXAMPLES_AC_RPS_HPP
#define CRYPTO12381_EXAMPLES_AC_RPS_HPP

#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::ac_rps 
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
    
    //(A, B)
    struct Signature : serialized_field<G1^2>{};
    
    //tilde_C_J
    struct RedactCache : serialized_field<G2>{};
    
    //(A_, B_, D_, tilde_C_J, U, s)
    struct PresInfo : serialized_field<G1^3, G2, GT, Zp>{};

    Keys keygen(size_t n, RandomEngine& random);

    std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random);

    Signature issue(const Keys& keys, std::span<serialized_field<Zp>> attr, RandomEngine& random);

    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk);

    PresInfo pres(std::span<const char> m, std::span<serialized_field<Zp>> attr, const Signature& sig, 
        std::span<const size_t> I, const RedactCache& redact_cache, const PublicKey& pk, RandomEngine& random);

    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, 
        const PresInfo& pres, const PublicKey& pk);
}

#endif