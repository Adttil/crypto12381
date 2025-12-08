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

    std::vector<Cred> cred_iss(
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

        // coefficient of shamir share 
        auto a = random-select_in<Zp>(t - 1) | materialize;

        // (A, share of e)
        return serialize(A, polynomial(x, e, std::move(a)))  (x.in[1, n + 1]);
    }

    std::vector<Cred> cred_pres(
        const PublicParameters& pp, 
        const PrivateKey& pk, 
        std::span<const Cred> creds,
        std::span<size_t> S,
        std::span<const serialized_field<Zp>> attributes,
        std::span<size_t> rev,
        RandomEngine& random
    )
    {
        return {};
        const size_t n = creds.size();
        const size_t t = S.size();
        
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        auto attr = parse<Zp>(attributes);

        auto r = random-select_in<Zp>;
        auto A = parse<G1>(creds[0].A);

        auto A_ = A^r;
    }
} 