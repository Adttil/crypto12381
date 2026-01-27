#include <crypto12381/crypto12381.hpp>
#include <AC-rbbs.hpp>
#include <optional>

namespace crypto12381::ac_rbbs
{
    RedactCache redact(std::span<serialized_field<Zp>> attr, const Signature& sig, std::span<const size_t> indexs, const PublicKey& pk)
    {
        auto [g, tilde_g, tilde_X] = parse<G1|G2^2>(pk.fixed_part);
        auto Y = parse<G1>(pk.Y) | materialize;
        auto a = parse<Zp>(attr) | materialize;
        const size_t n = a.size();
        auto [A, w] = parse<G1, Zp>(sig);
        auto I = indexs | algebraic;
        auto J = sequence(n)
            | filter([&](size_t i){ return not std::ranges::contains(I, i); });
        
        auto C_I = g * Π[i.in(I)](Y[i]^a[i]);
        auto B = C_I * (A^-w);
        auto C_J = Π[j.in(J)](Y[j]^a[j]);
        auto q = hash(a[j] (j.in(I)), i).to(Zp) (i.in[n]) | materialize;

        auto Yks = sequence(2*n)
            | std::views::transform([&](size_t k){
                auto valid_i = I
                | filter([&](size_t i){ return std::ranges::contains(J, k - n + i); });
                if(not valid_i.empty())
                {
                    return std::make_optional(Y[k]^Σ[i.in(valid_i)](q[i] * a[k - n + i])); 
                }
                return decltype(std::make_optional(Y[k]^Σ[i.in(valid_i)](q[i] * a[k - n + i]))){ std::nullopt };
            })
            | std::views::filter([](auto&& Yk){
                return Yk.has_value();
            })
            | transform([](auto&& Yk){
                return Yk.value();
            })
        ;

        auto D = Π(Yks);

        return serialize(C_I, C_J, B, D);
    }
}