#include <crypto12381/crypto12381.hpp>
#include <AC-rbbs.hpp>

namespace crypto12381::ac_rbbs
{
    PresInfo pres(std::span<const char> m, const Signature& sig, const RedactCache& redact_cache, RandomEngine& random)
    {
        auto [A, w] = parse<G1, Zp>(sig);
        auto [C_I, C_J, B, D] = parse<G1^4>(redact_cache);
        
        auto r = random-select_in<Zp>;

        auto A_ = A^r;
        auto B_ = B^r;
        auto C_J_ = C_J^r;
        auto D_ = D^r;

        auto [α, β] = random-select_in<Zp^2>;
        auto U = (C_I^α) * (A_^β);

        auto c = hash(m, A_, B_, C_J_, D_, U).to(Zp);

        auto s = α + r*c;
        auto t = β + -w*c;

        return serialize(A_, B_, C_J_, D_, U, s, t);
    }
}