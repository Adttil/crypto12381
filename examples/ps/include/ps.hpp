#ifndef CRYPTO12381_TESTS_PS_PS_HPP
#define CRYPTO12381_TESTS_PS_PS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

namespace crypto12381::ps 
{
    using namespace crypto12381;

    struct PrivateKey : serialized_field<Zp^2>{};

    struct PublicKey : serialized_field<G2^3>{};

    struct Keys
    {
        PrivateKey sk;
        PublicKey pk;
    };
    
    struct Signature : serialized_field<G1^2>{};
    
    Keys key_gen(RandomEngine& random);

    Signature sign(const PrivateKey& sk, std::span<const char> message, RandomEngine& random);

    bool verify(const PublicKey& pk, std::span<const char> message, const Signature& signature);

    Signature randomnize(const Signature& signature, RandomEngine& random);
}

namespace crypto12381::ps 
{
    struct PrivateKeyN
    {
        serialized_field<Zp> x;
        std::vector<serialized_field<Zp>> y;
    };

    struct PublicKeyN
    {
        serialized_field<G2> g2;
        serialized_field<G2> X2;
        std::vector<serialized_field<G2>> Y2;
    };

    struct KeysN
    {
        PrivateKeyN sk;
        PublicKeyN pk;
    };
    
    KeysN key_gen(size_t n, RandomEngine& random);

    Signature sign(const PrivateKeyN& sk, std::span<const char> message, RandomEngine& random);

    bool verify(const PublicKeyN& pk, std::span<const char> message, const Signature& signature);
}

#endif