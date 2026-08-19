#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/zp_number.hpp>

using namespace crypto12381;

namespace
{
    serialized_field<Zp> scalar_modulus()
    {
        constexpr std::array<unsigned char, 32> bytes{
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
            0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
            0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
        };

        serialized_field<Zp> result{};
        const auto offset = result.size() - bytes.size();
        for(std::size_t i = 0; i < bytes.size(); ++i)
        {
            result[offset + i] = static_cast<char>(bytes[i]);
        }
        return result;
    }
}

TEST_CASE("make_Zp represents zero and positive integers", "[Zp]")
{
    CHECK(make_Zp(0) == make_Zp(0u));
    CHECK(make_Zp(42) == make_Zp(std::uint64_t{ 42 }));
}

TEST_CASE("make_Zp represents negative integers", "[Zp]")
{
    CHECK(make_Zp(-42) + make_Zp(42) == make_Zp(0));
    CHECK(-make_Zp(-42) == make_Zp(42));
}

TEST_CASE("make_Zp represents large machine integers", "[Zp]")
{
    constexpr std::uint64_t value = std::numeric_limits<std::uint64_t>::max();

    CHECK(make_Zp(value) - make_Zp(value - 1) == make_Zp(1));
}

TEST_CASE("Zp addition and subtraction agree with integer arithmetic", "[Zp][arithmetic]")
{
    CHECK(make_Zp(17) + make_Zp(29) == make_Zp(46));
    CHECK(make_Zp(17) - make_Zp(29) == make_Zp(-12));
}

TEST_CASE("Zp multiplication agrees with integer arithmetic", "[Zp][arithmetic]")
{
    CHECK(make_Zp(123) * make_Zp(456) == make_Zp(56'088));
    CHECK(make_Zp(-123) * make_Zp(456) == make_Zp(-56'088));
}

TEST_CASE("Zp compile-time constant multiplication agrees with integer arithmetic", "[Zp][arithmetic]")
{
    CHECK(make_Zp(9) * constant<7> == make_Zp(63));
    CHECK(make_Zp(9) * constant<-7> == make_Zp(-63));
}

TEST_CASE("Zp division and inversion agree with integer arithmetic", "[Zp][arithmetic]")
{
    CHECK(make_Zp(84) / make_Zp(7) == make_Zp(12));
    CHECK(make_Zp(7) * inverse(make_Zp(7)) == make_Zp(1));
    CHECK(inverse(make_Zp(0)) == make_Zp(0));
}

TEST_CASE("Zp arithmetic reduces results modulo the scalar field order", "[Zp][arithmetic]")
{
    auto modulus_minus_one_bytes = scalar_modulus();
    --modulus_minus_one_bytes.back();
    const auto modulus_minus_one = parse<Zp>(modulus_minus_one_bytes);

    CHECK(modulus_minus_one + make_Zp(1) == make_Zp(0));
    CHECK(-make_Zp(1) == modulus_minus_one);
    CHECK(modulus_minus_one * modulus_minus_one == make_Zp(1));
}

TEST_CASE("Zp arithmetic satisfies field laws", "[Zp][arithmetic]")
{
    auto random = create_random_engine("Zp field law seed");

    for(int iteration = 0; iteration < 16; ++iteration)
    {
        CAPTURE(iteration);
        const auto [a, b, c] = random-select_in<*Zp ^ 3>;

        CHECK((a + b) + c == a + (b + c));
        CHECK(a + b == b + a);
        CHECK((a * b) * c == a * (b * c));
        CHECK(a * b == b * a);
        CHECK(a * (b + c) == (a * b) + (a * c));
        CHECK((a / b) * b == a);
    }
}

TEST_CASE("Zp multiplication handles values wider than one machine word", "[Zp][arithmetic]")
{
    constexpr std::uint64_t left = 4'000'000'000;
    constexpr std::uint64_t right = 4'000'000'001;
    constexpr std::uint64_t expected = left * right;

    CHECK(make_Zp(left) * make_Zp(right) == make_Zp(expected));
}

TEST_CASE("Zp wide intermediates compose with normalized values", "[Zp][arithmetic]")
{
    const auto a = make_Zp(6);
    const auto b = make_Zp(7);
    const auto c = make_Zp(4);
    const auto d = make_Zp(5);
    const auto first_product = a * b;
    const auto second_product = c * d;

    CHECK(first_product + second_product == make_Zp(62));
    CHECK(first_product - second_product == make_Zp(22));
    CHECK(first_product + c == make_Zp(46));
    CHECK(c + first_product == make_Zp(46));
    CHECK(first_product * c == make_Zp(168));
    CHECK(first_product / second_product == make_Zp(42) / make_Zp(20));
}

TEST_CASE("Zp serialization round-trips regular values", "[Zp][serialization]")
{
    auto random = create_random_engine("Zp serialization test seed");
    const auto original = random-select_in<Zp>;
    const serialized_field<Zp> bytes = serialize(original);

    CHECK(parse<Zp>(bytes) == original);
}

TEST_CASE("Zp serialization round-trips zero", "[Zp][serialization]")
{
    const auto zero = make_Zp(0);
    const serialized_field<Zp> bytes = serialize(zero);

    CHECK(parse<Zp>(bytes) == zero);
}

TEST_CASE("Zp parsing accepts the largest field element", "[Zp][serialization]")
{
    auto bytes = scalar_modulus();
    --bytes.back();

    CHECK_NOTHROW(parse<Zp>(bytes));
}

TEST_CASE("Zp parsing rejects the scalar field modulus", "[Zp][serialization]")
{
    CHECK_THROWS_AS(parse<Zp>(scalar_modulus()), std::runtime_error);
}

TEST_CASE("Zp parsing rejects values above the scalar field modulus", "[Zp][serialization]")
{
    serialized_field<Zp> bytes;
    bytes.fill(static_cast<char>(0xff));

    CHECK_THROWS_AS(parse<Zp>(bytes), std::runtime_error);
}

TEST_CASE("Zp message encoding accepts an empty message", "[Zp][encoding]")
{
    const auto encoded = encode_to<Zp>(std::span<const char>{});

    CHECK(encoded.empty());
}

TEST_CASE("Zp message encoding produces one element for one full chunk", "[Zp][encoding]")
{
    const std::string message(31, 'a');
    const auto encoded = encode_to<Zp>(std::span{ message.data(), message.size() });

    REQUIRE(encoded.size() == 1);
    CHECK(encoded[0] != make_Zp(0));
}

TEST_CASE("Zp message encoding splits a full and a partial chunk", "[Zp][encoding]")
{
    const std::string message(32, 'b');
    const auto encoded = encode_to<Zp>(std::span{ message.data(), message.size() });

    REQUIRE(encoded.size() == 2);
    CHECK(encoded[0] != make_Zp(0));
    CHECK(encoded[1] != make_Zp(0));
}

TEST_CASE("Zp polynomial evaluation uses every nonconstant coefficient", "[Zp][polynomial]")
{
    const std::array coefficients{ make_Zp(4), make_Zp(5) };
    const auto result = polynomial(3, make_Zp(2), coefficients);

    CHECK(result == make_Zp(59));
}

TEST_CASE("Zp polynomial evaluation accepts an empty coefficient range", "[Zp][polynomial]")
{
    const std::array<detail::Zp_normalized_t, 0> coefficients{};
    const auto result = polynomial(7, make_Zp(13), coefficients);

    CHECK(result == make_Zp(13));
}
