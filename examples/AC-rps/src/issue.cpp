#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    Signature issue(const Keys& keys, std::span<serialized_field<Zp>> attr, RandomEngine& random)
    {
        auto&&[sk, pk] = keys;
        auto[x, y] = parse<Zp^2>(sk);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        
        auto σ1 = random-select_in<*G1>;

        auto ym = [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i == n - 1)
            {
               return (a[i] * yn).normalize();
            }
            return (a[i] * yn + self(yn * y, i + 1)).normalize();
        }(y);

        auto σ2 = σ1^inverse(x + ym);

        return serialize(σ1, σ2);
    }
}