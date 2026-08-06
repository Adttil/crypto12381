#ifndef CRYPTO12381_EXAMPLES_AC_RPS_HPP
#define CRYPTO12381_EXAMPLES_AC_RPS_HPP

#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::ac_rps
{
    using namespace crypto12381;

    struct PrivateKey : serialized_field<Zp^2>{};

    struct UserSecretKey : serialized_field<Zp>{};

    struct UserPublicKey : serialized_field<G1>{};

    struct UserKeys
    {
        UserSecretKey usk;
        UserPublicKey upk;
    };

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

    //(h, sigma, tilde_M)
    struct Signature : serialized_field<G1^2, G2>{};

    //tilde_H
    struct RedactCache : serialized_field<G2>{};

    //(sigma1_, sigma2_, sigma3_, C, tilde_sigma_, c0, s0)
    struct PresInfo : serialized_field<G1^4, G2, Zp^2>{};

    Keys keygen(size_t n, RandomEngine& random);

    UserKeys user_keygen(const PublicKey& pk, RandomEngine& random);

    std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random);

    Signature issue(const Keys& keys, const UserPublicKey& upk, std::span<serialized_field<Zp>> attr, RandomEngine& random);

    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk);

    PresInfo pres(std::span<const char> m, std::span<serialized_field<Zp>> attr, const Signature& sig,
        std::span<const size_t> I, const RedactCache& redact_cache, const UserSecretKey& usk, const PublicKey& pk, RandomEngine& random);

    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I,
        const PresInfo& pres, const PublicKey& pk);
}

#endif
