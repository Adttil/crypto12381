#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    Signature issue(const Keys& keys, const UserPublicKey& upk, std::span<serialized_field<Zp>> attr, RandomEngine& random)
    {
        auto&&[sk, pk] = keys;
        auto [x, y] = parse<Zp^2>(sk);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Z = parse<G1>(upk);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();

        auto alpha = random-select_in<*Zp>;
        auto h = g^alpha;

        auto ym = [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i == n - 1uz)
            {
               return (a[i] * yn).normalize();
            }
            return (a[i] * yn + self(yn * y, i + 1uz)).normalize();
        }(y);

        auto y_user = [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i == n)
            {
                return yn.normalize();
            }
            return self((yn * y).normalize(), i + 1uz);
        }(y);

        auto sigma = (h^(x + ym)) * (Z^(alpha * y_user));
        auto tilde_M = Π[n](tilde_Y[i]^a[i]);

        return serialize(h, sigma, tilde_M);
    }
}
