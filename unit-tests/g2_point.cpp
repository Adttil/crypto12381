#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/g2_point.hpp>

using namespace crypto12381;

namespace
{
    auto select_g2(RandomEngine& random)
    {
        const serialized_field<G2> bytes = serialize(random-select_in<*G2>);
        return parse<G2>(bytes);
    }
}

TEST_CASE("G2 group operations satisfy their laws", "[G2][arithmetic]")
{
    auto random = create_random_engine("G2 group law seed");
    const auto first = select_g2(random);
    const auto second = select_g2(random);
    const auto third = select_g2(random);
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

TEST_CASE("G2 scalar multiplication satisfies module laws", "[G2][arithmetic]")
{
    auto random = create_random_engine("G2 scalar multiplication seed");
    const auto point = select_g2(random);
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

TEST_CASE("Selecting from nonidentity G2 excludes the identity", "[G2][random]")
{
    auto random = create_random_engine("nonidentity G2 seed");
    const auto reference = select_g2(random);
    const auto identity = reference / reference;

    for(int iteration = 0; iteration < 16; ++iteration)
    {
        CAPTURE(iteration);
        CHECK((random-select_in<*G2>) != identity);
    }
}

TEST_CASE("G2 serialization round-trips regular points", "[G2][serialization]")
{
    auto random = create_random_engine("G2 serialization test seed");
    const auto original = select_g2(random);
    const serialized_field<G2> bytes = serialize(original);

    CHECK(parse<G2>(bytes) == original);
}

TEST_CASE("G2 serialization round-trips the identity", "[G2][serialization]")
{
    auto random = create_random_engine("G2 identity test seed");
    const auto point = select_g2(random);
    const auto identity = point / point;
    const serialized_field<G2> bytes = serialize(identity);

    CHECK(parse<G2>(bytes) == identity);
}

TEST_CASE("G2 parsing rejects invalid encodings", "[G2][serialization]")
{
    serialized_field<G2> invalid_bytes{};
    invalid_bytes.front() = static_cast<char>(0x80);

    CHECK_THROWS_AS(parse<G2>(invalid_bytes), std::runtime_error);
}
