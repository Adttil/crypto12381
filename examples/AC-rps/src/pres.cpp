#include <optional>

#include <crypto12381/crypto12381.hpp>
#include <AC-rps.hpp>

namespace crypto12381::ac_rps
{
    PresInfo pres(std::span<const char> m, std::span<serialized_field<Zp>> attr, const Signature& sig, 
        std::span<const size_t> I, const RedactCache& redact_cache, const PublicKey& pk, RandomEngine& random)
    {
        auto a = parse<Zp>(attr);
        const size_t n = a.size();
        auto [A, B] = parse<G1^2>(sig);
        auto J = sequence(n) | filter([&](size_t i){ return not std::ranges::contains(I, i); });
        auto tilde_C_J = parse<G2>(redact_cache);
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y);
        auto tilde_Y = parse<G2>(pk.tilde_Y);
        
        auto [k, r, t] = random-select_in<Zp^3>;

        auto A_ = A^r;
        auto B_ = (B^r) * (A_^t);
        auto tilde_C_J_ = (tilde_g^t) * tilde_C_J;

        auto q = hash(A_, B_, tilde_C_J_, i).to(Zp) (i.in[n]) | materialize;

        auto Yks = sequence(2*n)
            | std::views::transform([&](size_t k){
                auto valid_i = I
                | filter([&](size_t i){ return std::ranges::contains(J, k - n + i); });
                bool has_t = std::ranges::contains(I, n - 1 - k);
                if(valid_i.empty() && not has_t)
                {
                    return decltype(std::make_optional(Y[k]^Σ[i.in(valid_i)](q[i] * a[k - n + i]).normalize())){ std::nullopt };
                }
                if(has_t)
                {
                    return std::make_optional(Y[k]^(t + Σ[i.in(valid_i)](q[i] * a[k - n + i])).normalize()); 
                }
                else
                {
                    return std::make_optional(Y[k]^Σ[i.in(valid_i)](q[i] * a[k - n + i]).normalize()); 
                }
            })
            | std::views::filter([](auto&& Yk){
                return Yk.has_value();
            })
            | transform([](auto&& Yk){
                return Yk.value();
            })
        ;

        auto D_ = Π(Yks);

        auto U = pair(A, tilde_Y[0]^k);

        auto c = hash(m, A_, B_, tilde_C_J_, D_, U).to(Zp);

        auto s = k + a[0]*c;
        // auto t = β + -w*c;

        return serialize(A_, B_, D_, tilde_C_J_, U, s);
    }
}