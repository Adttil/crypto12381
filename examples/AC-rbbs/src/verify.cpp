#include <crypto12381/crypto12381.hpp>
#include <AC-rbbs.hpp>

namespace crypto12381::ac_rbbs
{
    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, const PresInfo& pres, const PublicKey& pk)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A_, B_, C_J_, D_, U, s, t] = parse<G1^5|Zp^2>(pres);
        auto c = hash(m, A_, B_, C_J_, D_, U).to(Zp);
        auto q = hash(a[j] (j.in(I)), i).to(Zp) (i.in[n]) | materialize;

        return 
            pair(A_, tilde_X) == pair(C_J_ * B_, tilde_g)
            &&
            U * (B_^c) == ((g * Π[i.in(I)](Y[i]^a[i]))^s) * (A_^t)
            &&
            pair(C_J_, Π[i.in(I)](tilde_Y[n-1-i]^q[i])) == pair(D_, tilde_g)
        ;
    }
}