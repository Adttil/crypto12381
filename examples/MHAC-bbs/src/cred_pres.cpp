#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    Pres cred_pres(
        const PublicParameters& pp, 
        const PublicKey& pk, 
        const Creds& creds,
        std::span<const size_t> party_indexes,
        std::span<const size_t> Rev,
        std::span<const size_t> private_indexes,
        std::span<const serialized_field<Zp>> attrs,
        std::span<const std::vector<serialized_field<Zp>>> attr_shares,
        RandomEngine& random
    )
    {
        constexpr auto ii = make_symbol<"ii">();
        //constexpr auto ki = make_symbol<"ki">();
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto w = parse<G2>(pk);
        auto A = parse<G1>(creds.A);
        auto D_share = parse<G1>(creds.D);
        auto e_share = parse<Zp>(creds.e_share);
        auto a = parse<Zp>(attrs);
        auto a_share = parse<Zp>(attr_shares);

        //Zp_element auto a0_share0 = a_share[0][0];

        auto S = party_indexes | algebraic;
        auto Prv = private_indexes | algebraic;
        size_t j = 0;

        const size_t m = attrs.size();
        auto Hid = sequence(attrs.size())
            | filter([&](size_t i){ return not std::ranges::contains(Rev, i); });

        auto Hid_sub_Prv = Hid
            | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });

        auto I_Hid_sub_Prv = sequence(Hid.size())
            | filter([&](size_t i){ return not std::ranges::contains(Prv, Hid[i]); });

        const size_t t = S.size();

        auto x = make_Zp(i + 1) (i.in(S)) | materialize;
        //auto λi = Π[k.in[t].except(i)] (-x[k] / (x[i] - x[k]));
        auto λk = Π[y.in[t].except(k)] (-x[y] / (x[k] - x[y]));

        // //1. 
        auto r = random-select_in<Zp>;

        //2.
        G1_element auto A_ = A^r;
        G1_element auto D = Π[k.in[t]](D_share[S[k]]^λk);
        G1_element auto C_rev = g1 * Π[i.in(Rev)](h[i]^a[i]);
        G1_element auto C_pub = C_rev * Π[i.in(Hid_sub_Prv)](h[i]^a[i]);
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
        Zp_element auto ch = hash(U, A_, B_, a[i](i.in(Rev))).to(Zp);

        auto zii_share_j = β_share_j[ii] + ch*(r * a_share[S[j]][ii] * λk(k = j));
        //Prv[ii] in Prv
        auto zii_share_k = β_share_k[ii] + ch*(r * a_share[S[k]][ii] * λk);

        Zp_element auto zi0_share1 = zii_share_k(ii = 0, k = 1); 

        auto ze_share_k = (γ_share[k] + ch*(-e_share[S[k]] * λk));

        Zp_element auto zr = α + ch * r;

        //Hid[ii] in Hid
        auto zii_hid_pub = β_share_j[ii] + ch * (a[Hid[ii]] * r);

        //7.

        //8.
        auto zii = zii_share_j + Σ[k.in[1uz, t]](zii_share_k);
        // Zp_element auto zi0 = zii(ii = 0);
        // Zp_element auto zi1 = zii(ii = 1);
        Zp_element auto ze = Σ[k.in[t]](ze_share_k);

        return {
            .fixed_part = serialize(A_, B_, ch, zr, ze),
            .z = serialize(zii) (ii.in[Prv.size()]),
            .z_hid_pub = serialize(zii_hid_pub) (ii.in(I_Hid_sub_Prv))
        };
    }
} 