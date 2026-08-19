#include <catch2/catch_test_macros.hpp>

#include <crypto12381/liner_pair.hpp>

using namespace crypto12381;

namespace
{
    auto select_g1(RandomEngine& random)
    {
        const serialized_field<G1> bytes = serialize(random-select_in<*G1>);
        return parse<G1>(bytes);
    }

    auto select_g2(RandomEngine& random)
    {
        const serialized_field<G2> bytes = serialize(random-select_in<*G2>);
        return parse<G2>(bytes);
    }

    auto evaluate_pairing(const G1_element auto& first, const G2_element auto& second)
    {
        const serialized_field<GT> bytes = serialize(pair(first, second));
        return parse<GT>(bytes);
    }
}

TEST_CASE("Pairing is nondegenerate on nonidentity inputs", "[pairing]")
{
    auto random = create_random_engine("pairing nondegeneracy seed");
    const auto first = select_g1(random);
    const auto second = select_g2(random);
    const auto first_identity = first / first;
    const auto second_identity = second / second;
    const auto value = evaluate_pairing(first, second);
    const auto identity = evaluate_pairing(first_identity, second);

    CHECK(value != identity);
    CHECK(evaluate_pairing(first, second_identity) == identity);
}

TEST_CASE("Pairing is bilinear", "[pairing]")
{
    auto random = create_random_engine("pairing bilinearity seed");
    const auto first = select_g1(random);
    const auto second = select_g2(random);
    const auto [x, y] = random-select_in<Zp ^ 2>;
    const auto base = evaluate_pairing(first, second);

    SECTION("G1 exponent")
    {
        CHECK(pair(first ^ x, second) == (base ^ x));
    }

    SECTION("G2 exponent")
    {
        CHECK(pair(first, second ^ y) == (base ^ y));
    }

    SECTION("both exponents")
    {
        CHECK(pair(first ^ x, second ^ y) == (base ^ (x * y)));
    }
}

TEST_CASE("Double pairing matches two independent pairings", "[pairing]")
{
    auto random = create_random_engine("double pairing seed");
    const auto first_g1 = select_g1(random);
    const auto first_g2 = select_g2(random);
    const auto second_g1 = select_g1(random);
    const auto second_g2 = select_g2(random);

    const auto optimized = pair(first_g1, first_g2) * pair(second_g1, second_g2);
    const auto separate = evaluate_pairing(first_g1, first_g2) *
                          evaluate_pairing(second_g1, second_g2);

    CHECK(optimized == separate);
}

TEST_CASE("GT operations satisfy group and exponent laws", "[GT][arithmetic]")
{
    auto random = create_random_engine("GT group law seed");
    const auto first = evaluate_pairing(select_g1(random), select_g2(random));
    const auto second = evaluate_pairing(select_g1(random), select_g2(random));
    const auto identity = first / first;
    const auto [x, y] = random-select_in<Zp ^ 2>;

    SECTION("identity and inverse")
    {
        CHECK(first * identity == first);
        CHECK(first * inverse(first) == identity);
        CHECK(inverse(inverse(first)) == first);
    }

    SECTION("division reverses multiplication")
    {
        CHECK((first * second) / second == first);
    }

    SECTION("zero and one exponents")
    {
        CHECK((first ^ make_Zp(0)) == identity);
        CHECK((first ^ make_Zp(1)) == first);
    }

    SECTION("addition and multiplication in the exponent")
    {
        CHECK((first ^ (x + y)) == (first ^ x) * (first ^ y));
        CHECK((first ^ (x * y)) == ((first ^ x) ^ y));
    }
}

TEST_CASE("GT serialization", "[GT][serialization]")
{
    auto random = create_random_engine("GT serialization seed");
    const auto value = evaluate_pairing(select_g1(random), select_g2(random));

    SECTION("round trips pairing results")
    {
        const serialized_field<GT> bytes = serialize(value);

        CHECK(parse<GT>(bytes) == value);
    }

    SECTION("round trips the identity")
    {
        const auto identity = value / value;
        const serialized_field<GT> bytes = serialize(identity);

        CHECK(parse<GT>(bytes) == identity);
    }
}
