#include <array>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/algebra.hpp>

using namespace crypto12381;

TEST_CASE("Symbolic expressions substitute values", "[algebra]")
{
    static constexpr auto expression = x + y - 1;

    SECTION("all symbols at once")
    {
        STATIC_REQUIRE(expression(x = 3, y = 4) == 6);
    }

    SECTION("partial substitution")
    {
        static constexpr auto partially_substituted = expression(x = y + 3);

        STATIC_REQUIRE(partially_substituted(y = 5) == 12);
    }

    SECTION("positional functor")
    {
        static constexpr auto function = expression(x, y);

        STATIC_REQUIRE(function(3, 4) == 6);
    }
}

TEST_CASE("Ranged substitutions evaluate once for every supplied value", "[algebra]")
{
    static constexpr auto expression = x * x + 1;
    constexpr auto results = expression(x.in[1, 4]);

    STATIC_REQUIRE(results.size() == 3);
    STATIC_REQUIRE(results[0] == 2);
    STATIC_REQUIRE(results[1] == 5);
    STATIC_REQUIRE(results[2] == 10);
}

TEST_CASE("Symbolic subscripting works with algebraic ranges", "[algebra]")
{
    static constexpr auto values = std::array{ 2, 3, 5, 7, 11 } | algebraic;

    SECTION("single index")
    {
        STATIC_REQUIRE(values[i](i = 3) == 7);
    }

    SECTION("ranged index")
    {
        constexpr auto adjacent_sums = (values[i] + values[i + 1])(i.in[0, 4]);

        STATIC_REQUIRE(adjacent_sums.size() == 4);
        STATIC_REQUIRE(adjacent_sums[0] == 5);
        STATIC_REQUIRE(adjacent_sums[1] == 8);
        STATIC_REQUIRE(adjacent_sums[2] == 12);
        STATIC_REQUIRE(adjacent_sums[3] == 18);
    }
}

TEST_CASE("Algebraic range adaptors compose", "[algebra]")
{
    auto results = sequence(1, 8)
        | transform([](int value){ return value * value; })
        | filter([](int value){ return value % 2 == 0; })
        | materialize;

    REQUIRE(results.size() == 3);
    CHECK(results[0] == 4);
    CHECK(results[1] == 16);
    CHECK(results[2] == 36);
}

TEST_CASE("except removes every requested value", "[algebra]")
{
    auto results = sequence(1, 7) | except(2, 4, 6) | materialize;

    REQUIRE(results.size() == 3);
    CHECK(results[0] == 1);
    CHECK(results[1] == 3);
    CHECK(results[2] == 5);
}

TEST_CASE("unwrap exposes the underlying range", "[algebra]")
{
    std::array values{ 1, 2, 3 };
    auto wrapped = values | algebraic;
    auto&& unwrapped = wrapped | unwrap;

    STATIC_REQUIRE(std::same_as<decltype(unwrapped), std::array<int, 3>&>);
    CHECK(unwrapped.data() == values.data());
}
