#include <array>
#include <span>
#include <tuple>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/set.hpp>
#include <crypto12381/zp_number.hpp>
#include <crypto12381/g1_point.hpp>
#include <crypto12381/g2_point.hpp>

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
}

TEST_CASE("Cartesian powers select the requested number of Zp elements", "[set][random]")
{
    auto random = create_random_engine("Cartesian power selection seed");
    const auto selected = random-select_in<Zp ^ 3>;

    STATIC_REQUIRE(std::tuple_size_v<decltype(selected)> == 3);
    const auto& [first, second, third] = selected;
    const serialized_field<Zp> first_bytes = serialize(first);
    const serialized_field<Zp> second_bytes = serialize(second);
    const serialized_field<Zp> third_bytes = serialize(third);

    CHECK(parse<Zp>(first_bytes) == first);
    CHECK(parse<Zp>(second_bytes) == second);
    CHECK(parse<Zp>(third_bytes) == third);
}

TEST_CASE("Cartesian powers select the requested number of G1 elements", "[set][random]")
{
    auto random = create_random_engine("Cartesian power G1 selection seed");
    const auto selected = random-select_in<*G1 ^ 2>;

    STATIC_REQUIRE(std::tuple_size_v<decltype(selected)> == 2);
    const auto& [first, second] = selected;
    const serialized_field<G1> first_bytes = serialize(first);
    const serialized_field<G1> second_bytes = serialize(second);

    CHECK(parse<G1>(first_bytes) == first);
    CHECK(parse<G1>(second_bytes) == second);
}

TEST_CASE("Runtime-sized selection produces the requested number of elements", "[set][random]")
{
    auto random = create_random_engine("runtime selection seed");
    auto selected = random-select_in<Zp>(7) | materialize;

    REQUIRE(selected.size() == 7);
    for(const auto& value : selected)
    {
        const serialized_field<Zp> bytes = serialize(value);

        CHECK(parse<Zp>(bytes) == value);
    }
}

TEST_CASE("Combined serialization and parsing preserve heterogeneous elements", "[set][serialization]")
{
    auto random = create_random_engine("heterogeneous serialization seed");
    const auto scalar = random-select_in<Zp>;
    const auto first = select_g1(random);
    const auto second = select_g2(random);
    const serialized_field<Zp, G1, G2> bytes = serialize(scalar, first, second);

    const auto [parsed_scalar, parsed_first, parsed_second] = parse<Zp, G1, G2>(bytes);

    CHECK(parsed_scalar == scalar);
    CHECK(parsed_first == first);
    CHECK(parsed_second == second);
}

TEST_CASE("Cartesian set expressions parse serialized products", "[set][serialization]")
{
    auto random = create_random_engine("Cartesian set parsing seed");
    const auto scalar = random-select_in<Zp>;
    const auto first = select_g1(random);
    const auto second = select_g1(random);
    const serialized_field<Zp, G1 ^ 2> bytes = serialize(scalar, first, second);

    const auto [parsed_scalar, parsed_first, parsed_second] = parse<Zp | (G1 ^ 2)>(bytes);

    CHECK(parsed_scalar == scalar);
    CHECK(parsed_first == first);
    CHECK(parsed_second == second);
}

TEST_CASE("Serialization writes into caller-defined records", "[set][serialization]")
{
    struct Record : serialized_field<Zp, G1>
    {
    };

    auto random = create_random_engine("caller record serialization seed");
    const auto scalar = random-select_in<Zp>;
    const auto point = select_g1(random);
    const Record record = serialize(scalar, point);
    const auto [parsed_scalar, parsed_point] = parse<Zp, G1>(record);

    CHECK(parsed_scalar == scalar);
    CHECK(parsed_point == point);
}

TEST_CASE("Ranges of serialized fields parse lazily", "[set][serialization]")
{
    const std::array values{ make_Zp(3), make_Zp(5), make_Zp(8) };
    const std::array<serialized_field<Zp>, 3> bytes{
        serialize(values[0]),
        serialize(values[1]),
        serialize(values[2])
    };
    auto parsed = parse<Zp>(bytes) | materialize;

    REQUIRE(parsed.size() == values.size());
    for(std::size_t index = 0; index < values.size(); ++index)
    {
        CAPTURE(index);
        CHECK(parsed[index] == values[index]);
    }
}

TEST_CASE("Hashing equivalent element sequences produces the same Zp value", "[set][hash]")
{
    auto random = create_random_engine("hash equivalence seed");
    const auto [first, second, third] = random-select_in<Zp ^ 3>;
    const std::vector values{ first, second, third };

    const auto variadic = hash(first, second, third).to(Zp);
    const auto ranged = hash(values).to(Zp);
    const auto appended = (hash(first) | second | third).to(Zp);
    const auto piped = (hash | first | second | third).to(Zp);

    CHECK(variadic == ranged);
    CHECK(variadic == appended);
    CHECK(variadic == piped);
}

TEST_CASE("Hashing a Zp range is independent of its container type", "[set][hash]")
{
    auto random = create_random_engine("hash container seed");
    const auto [first, second, third] = random-select_in<Zp ^ 3>;
    const std::array array_values{ first, second, third };
    const std::vector vector_values{ first, second, third };

    CHECK(hash(array_values).to(Zp) == hash(vector_values).to(Zp));
}

TEST_CASE("Hashing a span depends on its elements instead of its storage", "[set][hash]")
{
    const std::vector<std::size_t> first_storage{ 1, 2, 3 };
    const std::vector<std::size_t> second_storage{ 1, 2, 3 };
    const std::span first{ first_storage };
    const std::span second{ second_storage };

    REQUIRE(first.data() != second.data());
    CHECK(hash(first).to(Zp) == hash(second).to(Zp));
}

TEST_CASE("Hashing is deterministic and order-sensitive", "[set][hash]")
{
    constexpr std::array first_message{ 'a', 'b', 'c' };
    constexpr std::array second_message{ 'c', 'b', 'a' };

    const auto first = hash(first_message).to(Zp);
    const auto repeated = hash(first_message).to(Zp);
    const auto reordered = hash(second_message).to(Zp);

    CHECK(first == repeated);
    CHECK(first != reordered);
}

TEST_CASE("Hashing to G1 is deterministic and message-dependent", "[set][hash][G1]")
{
    constexpr std::array first_message{ 'm', 'e', 's', 's', 'a', 'g', 'e' };
    constexpr std::array second_message{ 'M', 'e', 's', 's', 'a', 'g', 'e' };

    const auto first = hash(first_message).to(G1);
    const auto repeated = hash(first_message).to(G1);
    const auto changed = hash(second_message).to(G1);

    CHECK(first == repeated);
    CHECK(first != changed);
}

TEST_CASE("Generic sum and product directly aggregate Zp ranges", "[set][Zp]")
{
    const std::array values{ make_Zp(1), make_Zp(2), make_Zp(3), make_Zp(4) };

    CHECK(sum(values) == make_Zp(10));
    CHECK(product(values) == make_Zp(24));
}

TEST_CASE("Generic sum and product symbolically aggregate Zp ranges", "[set][Zp]")
{
    const std::array values{ make_Zp(1), make_Zp(2), make_Zp(3), make_Zp(4) };
    const auto algebraic_values = values | algebraic;

    CHECK(Σ[values.size()](algebraic_values[i]) == make_Zp(10));
    CHECK(Π[values.size()](algebraic_values[i]) == make_Zp(24));
}

TEST_CASE("Generic sum returns zero for an empty Zp range", "[set][Zp]")
{
    const std::array<decltype(make_Zp(0)), 0> empty{};

    CHECK(sum(empty) == make_Zp(0));
}

TEST_CASE("Generic sum aggregates wide Zp products", "[set][Zp]")
{
    const std::array products{
        make_Zp(2) * make_Zp(3),
        make_Zp(5) * make_Zp(7),
        make_Zp(11) * make_Zp(13)
    };

    CHECK(sum(products) == make_Zp(184));
}

TEST_CASE("Generic product aggregates nonempty G1 ranges", "[set][G1]")
{
    auto random = create_random_engine("G1 product seed");
    const auto first = select_g1(random);
    const auto second = select_g1(random);
    const auto third = select_g1(random);
    const std::array points{ first, second, third };

    CHECK(product(points) == (first * second) * third);
}

TEST_CASE("Generic product returns the identity for an empty G1 range", "[set][G1]")
{
    auto random = create_random_engine("empty G1 product seed");
    const auto point = select_g1(random);
    const std::array<decltype(point), 0> empty{};
    const auto identity = point / point;

    CHECK(product(empty) == identity);
}

TEST_CASE("Generic product aggregates lazy G1 powers", "[set][G1]")
{
    auto random = create_random_engine("G1 power product seed");
    const auto point = select_g1(random);
    const auto [x, y, z] = random-select_in<Zp ^ 3>;
    const std::array powers{ point ^ x, point ^ y, point ^ z };

    CHECK(product(powers) == (point ^ (x + y + z)));
}

TEST_CASE("Generic product aggregates nonempty G2 ranges", "[set][G2]")
{
    auto random = create_random_engine("G2 product seed");
    const auto first = select_g2(random);
    const auto second = select_g2(random);
    const auto third = select_g2(random);
    const std::array points{ first, second, third };

    CHECK(product(points) == (first * second) * third);
}

TEST_CASE("Generic product returns the identity for an empty G2 range", "[set][G2]")
{
    auto random = create_random_engine("empty G2 product seed");
    const auto point = select_g2(random);
    const std::array<decltype(point), 0> empty{};
    const auto identity = point / point;

    CHECK(product(empty) == identity);
}
