#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    bool verify(std::span<const char> m, std::span<serialized_field<Zp>> attr, std::span<const size_t> I, const PresInfo& pres, const PublicKey& pk)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A_, B_, D_, tilde_C_J_, U, s] = parse<G1^3|G2|GT|Zp>(pres);

        auto c = hash(m, A_, B_, tilde_C_J_, D_, U).to(Zp);
        auto q = hash(a[j] (j.in(I)), i).to(Zp) (i.in[n]) | materialize;

        bool t1 = pair(A_, tilde_Y[0]^s) * inverse(U) 
            == 
            ((
                pair(inverse(A_), tilde_X * tilde_C_J_ * Π[i.in(I).except(0)](tilde_Y[i]^a[i]))
                *
                pair(B_, tilde_g)
            )^c);
        bool t2 = pair(Π[i.in(I)](Y[n-1-i]^q[i]), tilde_C_J_) == pair(D_, tilde_g);
        return t1 && t2;
    }
}