#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    AttributesInfo generate_attributes(
        const PublicParameters& pp, 
        size_t t, 
        size_t n, 
        std::span<const size_t> private_indexes,
        RandomEngine& random
    )
    {
        constexpr auto ii = make_symbol<"ii">();

        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        size_t m = h.size();
        auto Prv = private_indexes | algebraic;
        auto Pub = sequence(m) | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });
        auto attr = random-select_in<Zp>(m) | materialize;

        auto a = random-select_in<Zp>(Prv.size() * (t - 1)) | materialize;
        
        auto attr_ii_a = a[j](j.in[ii * (t - 1), (ii + 1) * (t - 1)]);
        
        auto attr_ii_share = polynomial(x, attr[Prv[ii]], attr_ii_a)  (x.in[1, n + 1]);
        
        auto C = Π[ii.in[Prv.size()]](h[Prv[ii]]^attr_ii_share[k]) (k.in[n]);

        return { 
            .public_attributes = serialize(attr[i]) (i.in(Pub)),
            .private_attributes_share = serialize(attr_ii_share[k]) (ii.in[Prv.size()], k.in[n]),
            .commitments = serialize(C[j]) (j.in[n]) 
        };
    }

} 