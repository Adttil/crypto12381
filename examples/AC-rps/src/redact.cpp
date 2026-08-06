#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk)
    {
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        auto [h, sigma, tilde_M] = parse<G1^2|G2>(sig);

        auto tilde_H = tilde_M / Π[i.in(I)](tilde_Y[i]^a[i]);

        return serialize(tilde_H);
    }
}
