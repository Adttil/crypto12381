#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    Keys keygen(size_t n, RandomEngine& random)
    {
        auto g = random-select_in<*G1>;
        auto tilde_g = random-select_in<*G2>;
        auto [x, y] = random-select_in<Zp^2>;
        auto tilde_X = tilde_g^x;
    
        Keys keys{
            .sk = serialize(x, y),
            .pk = {
                .fixed_part = serialize(g, tilde_g, tilde_X),
                .Y{ 2uz * n },
                .tilde_Y{ n }
            }
        };

        [&](this auto&& self, auto&& yn, size_t i = 0uz){
            if(i >= 2uz * n)
            {
               return;
            }
            if(i < n)
            {
                keys.pk.tilde_Y[i] = serialize(tilde_g^yn);
            }
            if(i != n)
            {
                keys.pk.Y[i] = serialize(g^yn);
            }
            self(yn * y, i + 1);
        }(y);
        
        return keys;
    }
}