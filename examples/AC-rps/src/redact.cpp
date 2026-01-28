#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk)
    {
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto J = sequence(n)
            | filter([&](size_t i){ return not std::ranges::contains(I, i); });
        
        auto tilde_C_J = Π[j.in(J).except(0)](tilde_Y[j]^a[j]);

        return serialize(tilde_C_J);
    }
}