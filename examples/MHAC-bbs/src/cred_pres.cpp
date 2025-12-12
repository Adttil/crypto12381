#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    Pres cred_pres(
        const PublicParameters& pp,
        const Creds& creds,
        const PresGroup& group,
        const PresType& type,
        std::span<const size_t> private_indexes,
        std::span<const serialized_field<Zp>> public_attributes,
        std::span<const std::vector<serialized_field<Zp>>> attr_shares,
        RandomEngine& random
    )
    {
        constexpr auto ii = make_symbol<"ii">();

        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        const size_t m = h.size();
        auto A = parse<G1>(creds.A);
        auto D_share = parse<G1>(creds.D);
        auto e_share = parse<Zp>(creds.e_share);
        auto S = group.S | algebraic;
        auto λ = parse<Zp>(group.λ);
        auto D = parse<G1>(group.D);
        const auto& Rev = type.Rev;
        auto C_rev = parse<G1>(type.C_rev);
        auto C_pub = parse<G1>(type.C_pub);
        auto pub_a = parse<Zp>(public_attributes);
        auto a_share = parse<Zp>(attr_shares);
        
        auto Prv = private_indexes | algebraic;
        auto Pub = sequence(m) | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });
        
        size_t j = 0;

        
        auto Hid = sequence(m)
            | filter([&](size_t i){ return not std::ranges::contains(Rev, i); });

        auto HidPub = Hid
            | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });

        // auto I_Hid_sub_Prv = sequence(Hid.size())
        //     | filter([&](size_t i){ return not std::ranges::contains(Prv, Hid[i]); });

        auto I_Pub_in_Rev = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(Rev, Pub[i]); });

        auto I_Pub_in_Hid = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(Hid, Pub[i]); });

        const size_t t = S.size();

        //auto x = make_Zp(i + 1) (i.in(S)) | materialize;
        //auto λ = Π[y.in[t].except(k)] (-x[y] / (x[k] - x[y]))  (k.in[t]) | materialize;

        //1. 
        auto r = random-select_in<Zp>;

        //2.
        G1_element auto A_ = A^r;
        //G1_element auto D = Π[k.in[t]](D_share[S[k]]^λ[k]);
        //G1_element auto C_rev = g1 * Π[ii.in(I_Pub_in_Rev)](h[Pub[ii]]^pub_a[ii]);
        //G1_element auto C_pub = C_rev * Π[ii.in(I_Pub_in_Hid)](h[Pub[ii]]^pub_a[ii]);
        G1_element auto B_ = (C_pub * D)^r;

        //3.
        auto α = random-select_in<Zp>;
        auto β_share = random-select_in<Zp>((t - 1) * Prv.size()) | materialize;
        auto β_share_k = β_share[y] (y.in[(k - 1) * Prv.size(), k * Prv.size()]);
        auto β_share_j = random-select_in<Zp>(Hid.size()) | materialize;
        auto γ_share = random-select_in<Zp>(t) | materialize;

        G1_element auto Uj = ((C_rev^α) * Π[ii.in[Hid.size()]](h[Hid[ii]] ^ β_share_j[ii]) * (A_^γ_share[j]));

        auto Uk = Π[ii.in[Prv.size()]](h[Prv[ii]]^β_share_k[ii]) * (A_^γ_share[k]);

        //4.
        //5.

        //6.
        G1_element auto U = Uj * Π[k.in[t].except(j)](Uk);

        //Fixed me? with a(1, 2, 2) hash(a[0], a[1]) same as hash(a[0], a[2])
        Zp_element auto ch = hash(U, A_, B_, pub_a[ii](ii.in(I_Pub_in_Rev))).to(Zp);
        auto zii_share_j = β_share_j[ii] + ch*(r * a_share[S[j]][ii] * λ[j]);
        //Prv[ii] in Prv
        auto zii_share_k = β_share_k[ii] + ch*(r * a_share[S[k]][ii] * λ[k]);
        auto ze_share_k = (γ_share[k] + ch*(-e_share[S[k]] * λ[k]));
        Zp_element auto zr = α + ch * r;

        auto I_Pub_in_HidPub = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(HidPub, Pub[i]); });
        auto I_Hid_in_HidPub = sequence(Hid.size())
            | filter([&](size_t i){ return std::ranges::contains(HidPub, Hid[i]); });
        //Hid[ii] in Hid
        auto zii_hid_pub = β_share_j[I_Hid_in_HidPub[ii]] + ch * (pub_a[I_Pub_in_HidPub[ii]] * r);

        //7.

        //8.
        auto zii = zii_share_j + Σ[k.in[1uz, t]](zii_share_k);
        Zp_element auto ze = Σ[k.in[t]](ze_share_k);

        return {
            .fixed_part = serialize(A_, B_, ch, zr, ze),
            .z = serialize(zii) (ii.in[Prv.size()]),
            .z_hid_pub = serialize(zii_hid_pub) (ii.in[HidPub.size()])
        };
    }
} 