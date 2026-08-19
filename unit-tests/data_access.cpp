#include <concepts>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/data_access.hpp>
#include <crypto12381/zp_number.hpp>

using namespace crypto12381;

TEST_CASE("Data access preserves the source object's reference qualifiers", "[data_access]")
{
    auto value = make_Zp(7);
    const auto constant_value = make_Zp(11);

    STATIC_REQUIRE(std::same_as<
        decltype(value | detail::data),
        detail::ZpNumberData&
    >);
    STATIC_REQUIRE(std::same_as<
        decltype(constant_value | detail::data),
        const detail::ZpNumberData&
    >);
    STATIC_REQUIRE(std::same_as<
        decltype(std::move(value) | detail::data),
        detail::ZpNumberData&&
    >);

    CHECK(constant_value == make_Zp(11));
}
