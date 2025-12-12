#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    bool verify_pres(
        const PublicParameters& pp, 
        const PublicKey& pk,
        const PresType& type,
        std::span<const size_t> private_indexes,
        std::span<const serialized_field<Zp>> public_attributes,
        const Pres& pres
    )
    {
        constexpr auto ii = make_symbol<"ii">();

        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto w = parse<G2>(pk);
        const auto& Rev = type.Rev;
        auto C_rev = parse<G1>(type.C_rev);
        auto Prv = private_indexes | algebraic;
        auto pub_a = parse<Zp>(public_attributes);
        auto [A_, B_, ch, zr, ze] = parse<G1^2 | Zp^3>(pres.fixed_part);
        auto z = parse<Zp>(pres.z);
        auto z_hid_pub = parse<Zp>(pres.z_hid_pub);

        const size_t m = h.size();
        auto Hid = sequence(m)
            | filter([&](size_t i){ return not std::ranges::contains(Rev, i); });
        auto Hid_Pub = Hid
            | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });

        auto Pub = sequence(m) | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });
        auto I_Pub_in_Rev = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(Rev, Pub[i]); });

        //G1_element auto C_rev = g1 * Π[ii.in(I_Pub_in_Rev)](h[Pub[ii]]^pub_a[ii]);
        G1_element auto C_hid = 
            Π[ii.in[Prv.size()]](h[Prv[ii]]^z[ii]) 
            * 
            Π[ii.in[Hid_Pub.size()]](h[Hid_Pub[ii]]^z_hid_pub[ii]);
        G1_element auto U = (B_^-ch) * (C_rev^zr) * C_hid * (A_^ze);

        return ch == hash(U, A_, B_, pub_a[ii](ii.in(I_Pub_in_Rev))).to(Zp) && pair(A_, w) == pair(B_, g2);
    }
}