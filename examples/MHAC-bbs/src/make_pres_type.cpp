#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{    
    PresType make_pres_type(
        const PublicParameters& pp, 
        std::span<const size_t> Rev,
        std::span<const size_t> Prv,
        std::span<const serialized_field<Zp>> public_attributes
    )
    {
        constexpr auto ii = make_symbol<"ii">();
        auto [g1, g2] = parse<G1, G2>(pp.g1_g2);
        auto h = parse<G1>(pp.h);
        const size_t m = h.size();

        auto pub_a = parse<Zp>(public_attributes);
        
        auto Pub = sequence(m) | filter([&](size_t i){ return not std::ranges::contains(Prv, i); });

        auto Hid = sequence(m)
            | filter([&](size_t i){ return not std::ranges::contains(Rev, i); });

        auto I_Pub_in_Rev = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(Rev, Pub[i]); });
        auto I_Pub_in_Hid = sequence(Pub.size())
            | filter([&](size_t i){ return std::ranges::contains(Hid, Pub[i]); });

        G1_element auto C_rev = g1 * Π[ii.in(I_Pub_in_Rev)](h[Pub[ii]]^pub_a[ii]);
        G1_element auto C_pub = C_rev * Π[ii.in(I_Pub_in_Hid)](h[Pub[ii]]^pub_a[ii]);

        return {
            .Rev = Rev,
            .C_rev = serialize(C_rev),
            .C_pub = serialize(C_pub)
        };
    }
}