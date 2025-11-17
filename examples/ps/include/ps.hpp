#ifndef CRYPTO12381_TESTS_PS_PS_HPP
#define CRYPTO12381_TESTS_PS_PS_HPP
#include <algorithm>
#include <vector>
#include <ranges>
#include <stdexcept>
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

namespace crypto12381::ps 
{
    using namespace crypto12381;

    struct As
    {
        struct {
            Signature default_signature;
            serialized_field<G2^2> other_data;
        } pp;

        static As setup(RandomEngine& random);
        
        struct PrivateKey : serialized_field<Zp>{};
        struct PublicKey : serialized_field<G2>{};

        struct Keys{
            PrivateKey sk;
            PublicKey pk;
        };

        Keys key_gen(RandomEngine& random) const;

        template<typename RPk, typename RM>
        Signature sign(const Keys& keys, std::span<const char> message, RPk&& pks, RM&& messages, const Signature& signature, RandomEngine& random) const
        {
            auto& [sk, pk] = keys;
            size_t r = std::ranges::size(pks);
            if(r == 0)
            {
                return sign_no_check(sk, message, pp.default_signature, random);
            }
            if(not verify(pks, std::forward<RM>(messages), signature))
            {
                throw std::runtime_error{ "invalid signature" };
            }
            if(std::ranges::contains(std::forward<RPk>(pks), pk))
            {
                throw std::runtime_error{ "repetitive pk" };
            }
            return sign_no_check(sk, message, signature, random);
        }

        template<std::ranges::range RPk, std::ranges::range RM>
        bool verify(RPk&& pks, RM&& messages, const Signature& signature) const
        {
            auto pk_refs = pks | std::ranges::to<std::vector<std::reference_wrapper<const PublicKey>>>();
            if constexpr(std::convertible_to<RM&, std::span<std::span<const char>>>)
            {
                return verify_impl(pk_refs, messages, signature);
            }
            else
            {
                auto m = messages | std::ranges::to<std::vector<std::span<const char>>>();
            
                return verify_impl(pk_refs, m, signature);
            }
        }

        Signature sign_no_check(const PrivateKey& sk, std::span<const char> message, const Signature& signature, RandomEngine& random) const;

        bool verify_impl(std::span<std::reference_wrapper<const PublicKey>> pks, std::span<std::span<const char>> messages, const Signature& signature) const;
    };
}


#endif