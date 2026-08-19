#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/crypto12381.hpp>

using namespace crypto12381;

TEST_CASE("The aggregate header exposes the core mathematical interface", "[crypto12381]")
{
    STATIC_REQUIRE(Zp_element<decltype(make_Zp(1))>);
    STATIC_REQUIRE(G1_element<decltype(select_in<G1>(std::declval<RandomEngine&>()))>);
    STATIC_REQUIRE(G2_element<decltype(select_in<G2>(std::declval<RandomEngine&>()))>);
    STATIC_REQUIRE(GT_element<decltype(pair(
        select_in<G1>(std::declval<RandomEngine&>()),
        select_in<G2>(std::declval<RandomEngine&>())))>);
}
