#include <tuple>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/interface.hpp>

using namespace crypto12381;

TEST_CASE("Serialized sizes compose at compile time", "[interface]")
{
    STATIC_REQUIRE(serialized_size<Zp> == 48);
    STATIC_REQUIRE(serialized_size<G1> == 49);
    STATIC_REQUIRE(serialized_size<G2> == 97);
    STATIC_REQUIRE(serialized_size<GT> == 576);

    STATIC_REQUIRE(serialized_size<G1 ^ 3> == 3 * serialized_size<G1>);
    STATIC_REQUIRE(serialized_size<(G1 ^ 2) ^ 3> == 6 * serialized_size<G1>);
    STATIC_REQUIRE(sizeof(serialized_field<Zp, G1, G2>) ==
                   serialized_size<Zp> + serialized_size<G1> + serialized_size<G2>);
}
