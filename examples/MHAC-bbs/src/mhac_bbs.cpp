#include <iostream>
#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    IssSetupResult iss_setup(size_t m, RandomEngine& random) noexcept
    {
        auto pp = bbs::setup(m, random);
        auto keys = bbs::key_gen(pp, random);
        return IssSetupResult{ pp, keys };
    }

    AttributesInfo generate_attributes(
        const PublicParameters& pp, 
        size_t t, 
        size_t n, 
        std::span<const size_t> private_indexes,
        RandomEngine& random
    )
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        size_t m = h.size();
        auto Prv = private_indexes | algebraic;
        auto attr = random-select_in<Zp>(m) | materialize;

        auto a = random-select_in<Zp>(Prv.size() * (t - 1)) | materialize;
        auto attr_i_a = a[j](j.in[i * (t - 1), (i + 1) * (t - 1)]);
        auto attr_i_share = polynomial(x, attr[Prv[i]], attr_i_a)  (x.in[1, n + 1]);
        auto C = Π[i.in[Prv.size()]](h[Prv[i]]^attr_i_share[j]) (j.in[n]);

        return { 
            .attributes = serialize(attr[i]) (i.in[m]),
            .private_attributes_share = serialize(attr_i_share[j]) (i.in[Prv.size()], j.in[n]),
            .commitments = serialize(C[j]) (j.in[n]) 
        };
    }

    // std::vector<serialized_field<G1>> vss_of_private_attributes(
    //     const PublicParameters& pp,
    //     size_t t,
    //     size_t n,
    //     std::span<const size_t> private_indexes,
    //     std::span<const serialized_field<Zp>> attributes, 
    //     RandomEngine& random
    // )
    // {
    //     auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
    //     auto h = parse<G1>(pp.h);
    //     auto Prv = private_indexes | algebraic;
    //     auto attr = parse<Zp>(attributes);
    //     const size_t m = attributes.size();
    //     if(m > h.size())
    //     {
    //         throw std::runtime_error{ "attributes is too many" };
    //     }

    //     auto a = random-select_in<Zp>(m * (t - 1)) | materialize;
        
    //     auto attr_i_a = a[j](j.in[i * (t - 1), (i + 1) * (t - 1)]);

    //     symbolic auto attr_i_share = polynomial(x, attr[i], attr_i_a)  (x.in[1, n + 1]);

    //     auto Cj = Π[i.in(Prv)](h[i]^attr_i_share[j]);

    //     G1_element auto C0 = Cj (j = 0);

    //     return serialize(Cj) (j.in[n]);
    // }

    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        size_t n, 
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    )
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto γ = parse<Zp>(sk);
        auto attr = parse<Zp>(attributes);

        size_t m = attr.size();
        if(m > h.size())
        {
            throw std::runtime_error{ "attributes is too many" };
        }

        //BBS sign
        auto e = random-select_in<Zp>;
        auto A = (g1 * Π[m](h[i]^attr[i]))^inverse(γ + e);

        // share e
        auto a = random-select_in<Zp>(t - 1) | materialize;
        auto e_share = polynomial(x, e, a)  (x.in[1, n + 1]) | materialize;

        auto Di = A^-e_share[i];

        return {
            .A = serialize(A),
            .e_share = serialize(e_share[i]) (i.in[n]),
            .D = serialize(Di)  (i.in[n])
        };
    }

    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        std::span<const serialized_field<G1>> commitment,
        std::span<const size_t> public_indexes,
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    )
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto γ = parse<Zp>(sk);
        const size_t n = commitment.size();
        auto C = parse<G1>(commitment);
        auto Pub = public_indexes | algebraic;
        auto attr = parse<Zp>(attributes);

        size_t m = attr.size();
        if(m > h.size())
        {
            throw std::runtime_error{ "attributes is too many" };
        }
        
        auto C_a = [&](){
            auto x = make_Zp(i) (i.in[1, t + 1]) | materialize;
            auto λi = Π[j.in[t].except(i)] (-x[j] / (x[i] - x[j]));
            return g1 * Π[t](C[i]^λi) * Π[i.in(Pub)](h[i]^attr[i]);
        }();

        //BBS sign
        Zp_element auto e = random-select_in<Zp>;
        G1_element auto A = C_a^inverse(γ + e);

        // share e 
        auto a = random-select_in<Zp>(t - 1) | materialize;
        auto e_share = polynomial(x, e, a)  (x.in[1, n + 1]) | materialize;

        auto Di = C[i] * (A^-e_share[i]);

        return {
            .A = serialize(A),
            .e_share = serialize(e_share[i]) (i.in[n]),
            .D = serialize(Di) (i.in[n])
        };
    }

    Pres cred_pres(
        const PublicParameters& pp, 
        const PublicKey& pk, 
        const Creds& creds,
        std::span<size_t> party_indexes,
        std::span<const serialized_field<Zp>> attributes,
        std::span<size_t> Rev,
        std::span<size_t> Prv,
        RandomEngine& random
    )
    {
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto w = parse<G2>(pk);
        auto A = parse<G1>(creds.A);
        auto D_share = parse<G1>(creds.D);
        auto e_share = parse<Zp>(creds.e_share);
        auto a = parse<Zp>(attributes);

        auto S = party_indexes | algebraic;
        size_t j = S[0];

        auto Hid = sequence(attributes.size())
            | filter([&](size_t i){ return not std::ranges::contains(Rev, i); });

        auto Hid_sub_Prv = Hid
            | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });

        const size_t t = party_indexes.size();

        auto x = make_Zp(i + 1) (i.in(party_indexes)) | materialize;
        auto λi = Π[k.in[t].except(i)] (-x[k] / (x[i] - x[k]));

        //1. 
        auto r = random-select_in<Zp>;

        //2.
        G1_element auto A_ = A^r;
        G1_element auto D = Π[t](D_share[i]^λi);
        G1_element auto C_rev = g1 * Π[i.in(Rev)](h[i]^a[i]);
        G1_element auto C_pub = C_rev * Π[i.in(Hid_sub_Prv)](h[i]^a[i]);
        G1_element auto B_ = (C_pub * D)^r;

        //3.
        auto α_share = random-select_in<Zp>(t) | materialize;
        auto β_share = random-select_in<Zp>(t * Hid.size()) | materialize;
        auto β_i_share = β_share[k] (k.in[i * t, (i + 1) * t]);
        auto γ_share = random-select_in<Zp>(t) | materialize;

        G1_element auto U_j = ((C_rev^α_share[j]) * Π[i.in(Hid)](h[i] ^ subscript(β_i_share, j)) * (A_^γ_share[j]));

        auto U_k = ((C_rev^α_share[k]) * Π[i.in(Hid)](h[i]^β_i_share[k]) * (A_^γ_share[k]));

        //4.
        //5.

        //6.
        G1_element auto U = U_j * Π[k.in(S).except(j)](U_k);
        Zp_element auto ch = hash(U, A_, B_, a[i](i.in(Rev))).to(Zp);

        //auto zi_shares = β_i_share[k] + ch*(r * )

        return {};
        // const size_t n = creds.size();
        // const size_t t = S.size();
        
        // auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        // auto h = parse<G1>(pp.h);
        // auto attr = parse<Zp>(attributes);

        // auto r = random-select_in<Zp>;
        // auto A = parse<G1>(creds[0].A);

        // auto A_ = A^r;
    }
} 