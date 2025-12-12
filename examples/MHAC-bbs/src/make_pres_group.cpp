#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    PresGroup make_pres_group(const Creds& creds, std::span<const size_t> party_indexes)
    {
        auto D_share = parse<G1>(creds.D);
        auto S = party_indexes | algebraic;
        size_t t = S.size();

        auto x = make_Zp(i + 1) (i.in(S)) | materialize;
        auto λ = Π[y.in[t].except(k)] (-x[y] / (x[k] - x[y]))  (k.in[t]) | materialize;

        G1_element auto D = Π[k.in[t]](D_share[S[k]]^λ[k]);

        return {
            .S = party_indexes,
            .λ = serialize(λ[k]) (k.in[t]),
            .D = serialize(D)
        };
    }
}