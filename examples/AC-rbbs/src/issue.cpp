#include <crypto12381/crypto12381.hpp>
#include <AC-rbbs.hpp>

namespace crypto12381::ac_rbbs
{
    Signature issue(const Keys& keys, std::span<serialized_field<Zp>> attr, RandomEngine& random)
    {
        auto&&[sk, pk] = keys;
        auto[x, y] = parse<Zp^2>(sk);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        
        auto w = random-select_in<*Zp>;
        auto A = (g * Π[n](Y[i]^a[i]))^inverse(x + w);

        return serialize(A, w);
    }
}