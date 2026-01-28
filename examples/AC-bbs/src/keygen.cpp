#include <crypto12381/crypto12381.hpp>
#include <AC-bbs.hpp>

namespace crypto12381::ac_bbs
{
    Keys keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto x = random-select_in<Zp>;
        auto tilde_X = tilde_g^x;
        auto Y = random-select_in<*G1>(n);

        return {
            .sk = serialize(x),
            .pk = {
                .fixed_part = serialize(g, tilde_g, tilde_X),
                .Y = serialize(Y[i]) (i.in[n])
            }
        };
    }
}