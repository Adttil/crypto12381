#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    /*Creds cred_iss(
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
    }*/

    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        std::span<const serialized_field<G1>> commitment,
        std::span<const size_t> public_indexes,
        std::span<const serialized_field<Zp>> public_attributes, 
        RandomEngine& random
    )
    {
        auto ii = make_symbol<"ii">();

        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto γ = parse<Zp>(sk);
        const size_t n = commitment.size();
        auto C = parse<G1>(commitment);
        auto Pub = public_indexes | algebraic;
        auto pub_a = parse<Zp>(public_attributes);

        size_t m = h.size();
        
        G1_element auto C_a = [&](){
            auto x = make_Zp(i) (i.in[1, t + 1]) | materialize;
            auto λi = Π[j.in[t].except(i)] (-x[j] / (x[i] - x[j]));
            return g1 * Π[t](C[i]^λi) * Π[ii.in[Pub.size()]](h[Pub[ii]]^pub_a[ii]);
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
} 