#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/g1_point.hpp>

using namespace crypto12381;

namespace
{
    auto select_g1(RandomEngine& random)
    {
        const serialized_field<G1> bytes = serialize(random-select_in<*G1>);
        return parse<G1>(bytes);
    }
}

TEST_CASE("G1 group operations satisfy their laws", "[G1][arithmetic]")
{
    auto random = create_random_engine("G1 group law seed");
    const auto first = select_g1(random);
    const auto second = select_g1(random);
    const auto third = select_g1(random);
    const auto identity = first / first;

    SECTION("identity")
    {
        CHECK(first * identity == first);
        CHECK(identity * first == first);
        CHECK(first / first == identity);
    }

    SECTION("inverse")
    {
        CHECK(first * inverse(first) == identity);
        CHECK(inverse(inverse(first)) == first);
    }

    SECTION("commutativity and associativity")
    {
        CHECK(first * second == second * first);
        CHECK((first * second) * third == first * (second * third));
    }

    SECTION("subtraction reverses addition")
    {
        CHECK((first * second) / second == first);
    }
}

TEST_CASE("G1 scalar multiplication satisfies module laws", "[G1][arithmetic]")
{
    auto random = create_random_engine("G1 scalar multiplication seed");
    const auto point = select_g1(random);
    const auto identity = point / point;
    const auto [x, y] = random-select_in<Zp ^ 2>;

    SECTION("zero and one scalars")
    {
        CHECK((point ^ make_Zp(0)) == identity);
        CHECK((point ^ make_Zp(1)) == point);
    }

    SECTION("addition in the exponent")
    {
        CHECK((point ^ (x + y)) == (point ^ x) * (point ^ y));
    }

    SECTION("multiplication in the exponent")
    {
        CHECK((point ^ (x * y)) == ((point ^ x) ^ y));
    }

    SECTION("negative exponent")
    {
        CHECK((point ^ -x) == inverse(point ^ x));
    }
}

TEST_CASE("G1 double scalar multiplication matches separate operations", "[G1][arithmetic]")
{
    auto random = create_random_engine("G1 double multiplication seed");

    for(int iteration = 0; iteration < 8; ++iteration)
    {
        CAPTURE(iteration);
        const auto first = select_g1(random);
        const auto second = select_g1(random);
        const auto [x, y] = random-select_in<Zp ^ 2>;

        const auto optimized = (first ^ x) * (second ^ y);
        const auto first_product = parse<G1>(static_cast<serialized_field<G1>>(serialize(first ^ x)));
        const auto second_product = parse<G1>(static_cast<serialized_field<G1>>(serialize(second ^ y)));
        const auto separate = first_product * second_product;

        CHECK(optimized == separate);
    }
}

TEST_CASE("Selecting from nonidentity G1 excludes the identity", "[G1][random]")
{
    auto random = create_random_engine("nonidentity G1 seed");
    const auto reference = select_g1(random);
    const auto identity = reference / reference;

    for(int iteration = 0; iteration < 16; ++iteration)
    {
        CAPTURE(iteration);
        CHECK((random-select_in<*G1>) != identity);
    }
}

TEST_CASE("G1 serialization round-trips regular points", "[G1][serialization]")
{
    auto random = create_random_engine("G1 serialization test seed");
    const auto original = select_g1(random);
    const serialized_field<G1> bytes = serialize(original);

    CHECK(parse<G1>(bytes) == original);
}

TEST_CASE("G1 serialization round-trips the identity", "[G1][serialization]")
{
    auto random = create_random_engine("G1 identity test seed");
    const auto point = select_g1(random);
    const auto identity = point / point;
    const serialized_field<G1> bytes = serialize(identity);

    CHECK(parse<G1>(bytes) == identity);
}

TEST_CASE("G1 parsing rejects invalid encodings", "[G1][serialization]")
{
    serialized_field<G1> invalid_bytes;
    invalid_bytes.fill(static_cast<char>(0xff));

    CHECK_THROWS_AS(parse<G1>(invalid_bytes), std::runtime_error);
}
