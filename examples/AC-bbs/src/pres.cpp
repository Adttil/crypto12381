#include <crypto12381/crypto12381.hpp>
#include <AC-bbs.hpp>

namespace crypto12381::ac_bbs
{
    PresInfo pres(std::span<const char> m, std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> I, const PublicKey& pk, RandomEngine& random)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A, w] = parse<G1, Zp>(sig);
        auto J = sequence(n)
            | filter([&](size_t i){ return not std::ranges::contains(I, i); });
        
        auto C_I = g * Π[i.in(I)](Y[i]^a[i]);
        auto C_J = Π[j.in(J)](Y[j]^a[j]);
        
        auto r = random-select_in<Zp>;

        auto A_ = A^r;
        
        auto B_ = ((C_I * C_J)^r) * (A_^-w);
        

        auto [α, β] = random-select_in<Zp^2>;
        auto δ = random-select_in<Zp>(J.size()) | materialize;

        auto U = (C_I^α) * (A_^β) * Π[j.in[J.size()]](Y[J[j]]^δ[j]);

        auto c = hash(m, A_, B_, U).to(Zp);

        //auto rc = (r*c).normalize();
        auto s = α + r*c;
        auto t = β + -w*c;
        auto uj = δ[j] + r*c*a[J[j]];

        return {
            .fixed_part = serialize(A_, B_, U, s, t),
            .u = serialize(uj) (j.in[J.size()])
        };
    }
}