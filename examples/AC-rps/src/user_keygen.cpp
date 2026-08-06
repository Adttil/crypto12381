#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    UserKeys user_keygen(const PublicKey& pk, RandomEngine& random)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto usk = random-select_in<*Zp>;
        return {
            .usk = serialize(usk),
            .upk = serialize(g^usk)
        };
    }
}
