#include <crypto12381/crypto12381.hpp>
#include <bbs.hpp>

namespace crypto12381::bbs04
{
    Keys key_gen(size_t n, RandomEngine& random) noexcept
    {
        auto [g1, h] = random-select_in<*G1^2>;
        auto g2 = random-select_in<*G2>;
        auto [ξ1, ξ2, γ] = random-select_in<*Zp^3>;

        auto u = h^inverse(ξ1);
        auto v = h^inverse(ξ2);
        
        auto w = g2^γ;

        return {
            .gpk = serialize(g1, g2, h, u, v, w),
            .gmsk = serialize(ξ1, ξ2),
            .gsk = std::views::iota(0uz, n)
                | std::views::transform([&](auto) -> GroupMemberPrivateKey {
                    auto x = random-select_in<*Zp>;
                    auto A = g1^inverse(γ + x);
                    return serialize(A, x);
                })
                | std::ranges::to<std::vector>()
        };
    }

    Signature sign(const GroupPublicKey& gpk, const GroupMemberPrivateKey& gsk, std::span<const char> message, RandomEngine& random) noexcept
    {
        auto [g1, g2, h, u, v, w] = parse<G1, G2, G1, G1, G1, G2>(gpk);
        auto [A, x] = parse<G1, Zp>(gsk);

        auto [α, β, rα, rβ, rx, rδ1, rδ2] = random-select_in<Zp^7>;

        auto T1 = u^α;
        auto T2 = v^β;
        auto T3 = A * (h^(α + β));

        auto R1 = u^rα;
        auto R2 = v^rβ;
        auto R3 = pair((T3^rx) * (h^-(rδ1 + rδ2)), g2) * pair(h^-(rα + rβ), w);
        auto R4 = (T1^rx) * (u^-rδ1);
        auto R5 = (T2^rx) * (v^-rδ2);

        auto c = hash(message, T1, T2, T3, R1, R2, R3, R4, R5).to(Zp);

        auto sα = rα + c * α;
        auto sβ = rβ + c * β;
        auto cx = c * x;
        auto sx = rx + cx;
        auto sδ1 = rδ1 + α * cx; // α*(c*x) = c*(α*x) = c*δ1
        auto sδ2 = rδ2 + β * cx; // β*(c*x) = c*(β*x) = c*δ2

        return serialize(T1, T2, T3, c, sα, sβ, sx, sδ1, sδ2);
    }

    bool verify(const GroupPublicKey& gpk, std::span<const char> message, const Signature& signature) noexcept
    {
        auto [g1, g2, h, u, v, w] = parse<G1, G2, G1, G1, G1, G2>(gpk);
        auto [T1, T2, T3, c, sα, sβ, sx, sδ1, sδ2] = parse<G1, G1, G1, Zp, Zp, Zp, Zp, Zp, Zp>(signature);

        auto neg_c = -c;
        auto neg_sδ1 = -sδ1;
        auto neg_sδ2 = -sδ2;

        auto R1 = (u^sα) * (T1^neg_c);
        auto R2 = (v^sβ) * (T2^neg_c);

        auto R3 = pair((T3^sx) * (h^(neg_sδ1 + neg_sδ2)) / (g1^c), g2) * pair((h^-(sα + sβ)) * (T3^c), w);
        auto R4 = (T1^sx) * (u^neg_sδ1);
        auto R5 = (T2^sx) * (v^neg_sδ2);
        
        return c == hash(message, T1, T2, T3, R1, R2, R3, R4, R5).to(Zp);
    }

    serialized_field<G1> open(const GroupManagerPrivateKey& gmsk, const Signature& signature) noexcept
    {
        auto [T1, T2, T3, c, sα, sβ, sx, sδ1, sδ2] = parse<G1, G1, G1, Zp, Zp, Zp, Zp, Zp, Zp>(signature);
        auto&& [ξ1, ξ2] = parse<Zp^2>(gmsk);
        auto a = T3 / ((T1^ξ1) * (T2^ξ2));

        return serialize(a);
    }
} 