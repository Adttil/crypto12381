#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace crypto12381::bbs
{
    PublicParameters setup(size_t n, RandomEngine& random) noexcept
    {
        auto g1 = random-select_in<*G1>;
        auto g2 = random-select_in<*G2>;
        
        std::vector<serialized_field<G1>> h(n);
        for(size_t i = 0; i < n; ++i)
        {
            h[i] = serialize(random-select_in<*G1>);
        }

        return {
            .g1_g2 = serialize(g1, g2),
            .h  = std::move(h)
        };
    }

    Keys key_gen(const PublicParameters& pp, RandomEngine& random) noexcept
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        
        auto γ = random-select_in<*Zp>;

        auto w = g2^γ;

        return {
            .pk = serialize(w),
            .sk = serialize(γ)
        };
    }

    Signature sign(const PublicParameters& pp, const PrivateKey& sk, std::span<const char> message, RandomEngine& random)
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto γ = parse<Zp>(sk);
        auto m = encode_to<Zp>(message);

        size_t n = m.size();
        if(n > h.size())
        {
            throw std::runtime_error{ "message is too long" };
        }

        auto x = random-select_in<Zp>;
        
        auto A = (g1 * Π[n](h[i]^m[i]))^inverse(γ + x);
        return serialize(A, x);
    }

    bool verify(const PublicParameters& pp, const PublicKey& pk, std::span<const char> message, const Signature& signature)
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto w = parse<G2>(pk);
        auto m = encode_to<Zp>(message);

        size_t n = m.size();
        if(n > h.size())
        {
            throw std::runtime_error{ "message is too long" };
        }

        auto [A, x] = parse<G1, Zp>(signature);

        return pair(A, w * (g2^x)) == pair(g1 * Π[n](h[i]^m[i]), g2);
    }
} 