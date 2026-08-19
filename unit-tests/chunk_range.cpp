#include <catch2/catch_test_macros.hpp>

#include <crypto12381/chunk_range.hpp>

using crypto12381::constant;
using crypto12381::detail::ChunkRange;
using crypto12381::detail::sign;

TEST_CASE("ChunkRange containment includes its boundaries", "[ChunkRange]")
{
    constexpr ChunkRange range{ -4, 9 };

    STATIC_REQUIRE(range.contains({ -4, 9 }));
    STATIC_REQUIRE(range.contains({ 0, 0 }));
    STATIC_REQUIRE_FALSE(range.contains({ -5, 0 }));
    STATIC_REQUIRE_FALSE(range.contains({ 0, 10 }));
}

TEST_CASE("ChunkRange arithmetic bounds every possible result", "[ChunkRange]")
{
    constexpr ChunkRange left{ -2, 5 };
    constexpr ChunkRange right{ 3, 7 };

    SECTION("negation")
    {
        constexpr auto result = -left;
        STATIC_REQUIRE(result.min == -5);
        STATIC_REQUIRE(result.max == 2);
    }

    SECTION("addition")
    {
        constexpr auto result = left + right;
        STATIC_REQUIRE(result.min == 1);
        STATIC_REQUIRE(result.max == 12);
    }

    SECTION("subtraction")
    {
        constexpr auto result = left - right;
        STATIC_REQUIRE(result.min == -9);
        STATIC_REQUIRE(result.max == 2);
    }

    SECTION("range multiplication")
    {
        constexpr auto result = left * right;
        STATIC_REQUIRE(result.min == -14);
        STATIC_REQUIRE(result.max == 35);
    }

    SECTION("positive constant multiplication")
    {
        constexpr auto result = left * constant<3>;
        STATIC_REQUIRE(result.min == -6);
        STATIC_REQUIRE(result.max == 15);
    }

    SECTION("negative constant multiplication")
    {
        constexpr auto result = left * constant<-3>;
        STATIC_REQUIRE(result.min == -15);
        STATIC_REQUIRE(result.max == 6);
    }
}

TEST_CASE("ChunkRange division reports safe accumulation counts", "[ChunkRange]")
{
    STATIC_REQUIRE((ChunkRange{ -100, 100 } / ChunkRange{ 0, 10 }) == 10);
    STATIC_REQUIRE((ChunkRange{ -100, 100 } / ChunkRange{ -10, 0 }) == 10);
    STATIC_REQUIRE((ChunkRange{ 4, 12 } / ChunkRange{ 2, 3 }) == 2);
}

TEST_CASE("sign distinguishes negative, zero, and positive integers", "[ChunkRange]")
{
    STATIC_REQUIRE(sign(-11) == -1);
    STATIC_REQUIRE(sign(0) == 0);
    STATIC_REQUIRE(sign(11u) == 1);
}
