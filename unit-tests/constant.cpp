#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/constant.hpp>

using namespace crypto12381;

TEST_CASE("Compile-time constants retain their values and types", "[constant]")
{
    STATIC_REQUIRE(constant<7>.value == 7);
    STATIC_REQUIRE(constant<-3>.value == -3);
    STATIC_REQUIRE(std::same_as<std::remove_cvref_t<decltype(constant<7>)>, constant_t<7>>);
}
