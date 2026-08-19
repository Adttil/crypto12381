#include <catch2/catch_test_macros.hpp>

#include <crypto12381/general.hpp>

using namespace crypto12381::detail;

TEST_CASE("specified ignores cv-qualifiers and references", "[general]")
{
    STATIC_REQUIRE(specified<int, int>);
    STATIC_REQUIRE(specified<const int&, int>);
    STATIC_REQUIRE(specified<volatile int&&, int>);
    STATIC_REQUIRE_FALSE(specified<long, int>);
}
