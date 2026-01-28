#include <crypto12381/crypto12381.hpp>
#include <AC-bbs.hpp>

namespace crypto12381::ac_bbs
{
    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, const PresInfo& pres, const PublicKey& pk)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A_, B_, U, s, t] = parse<G1^3|Zp^2>(pres.fixed_part);
        auto u = parse<Zp>(pres.u);
        auto J = sequence(n)
            | filter([&](size_t i){ return not std::ranges::contains(I, i); });

        //std::println("J.size = {}", J.size());

        auto c = hash(m, A_, B_, U).to(Zp);

        return 
            pair(A_, tilde_X) == pair(B_, tilde_g)
            &&
            U * (B_^c) == ((g * Π[i.in(I)](Y[i]^a[i]))^s) * (A_^t) * Π[j.in[J.size()]](Y[J[j]]^u[j])
        ;
    }
}