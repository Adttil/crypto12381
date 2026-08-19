#include <catch2/catch_test_macros.hpp>

#include <crypto12381/random.hpp>
#include <crypto12381/zp_number.hpp>

using namespace crypto12381;

TEST_CASE("Random engines with the same seed produce the same sequence", "[random]")
{
    auto first = create_random_engine("repeatable seed");
    auto second = create_random_engine("repeatable seed");

    for(int i = 0; i < 8; ++i)
    {
        const serialized_field<Zp> first_value = serialize(first-select_in<Zp>);
        const serialized_field<Zp> second_value = serialize(second-select_in<Zp>);

        CHECK(first_value == second_value);
    }
}

TEST_CASE("Different random seeds produce different sequences", "[random]")
{
    auto first = create_random_engine("first seed");
    auto second = create_random_engine("second seed");
    const serialized_field<Zp> first_value = serialize(first-select_in<Zp>);
    const serialized_field<Zp> second_value = serialize(second-select_in<Zp>);

    CHECK(first_value != second_value);
}

TEST_CASE("Selecting from nonzero Zp never returns zero", "[random][Zp]")
{
    auto random = create_random_engine("nonzero Zp seed");

    for(int i = 0; i < 32; ++i)
    {
        CHECK((random-select_in<*Zp>) != make_Zp(0));
    }
}
