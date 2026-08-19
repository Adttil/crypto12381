#include <array>
#include <cstdint>

#include <catch2/catch_test_macros.hpp>

#include <crypto12381/miracl_core_interface.hpp>

using namespace crypto12381::detail;

TEST_CASE("The MIRACL SHA3 bridge computes the SHA3-512 empty digest", "[miracl_core_interface][hash]")
{
    constexpr std::array<std::uint8_t, 64> expected{
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
    };
    std::array<char, expected.size()> digest{};
    miracl_core::sha3_state state{};

    miracl_core::sha3_init(state, static_cast<int>(digest.size()));
    miracl_core::sha3_hash(state, digest.data());

    for(std::size_t index = 0; index < digest.size(); ++index)
    {
        CAPTURE(index);
        CHECK(static_cast<std::uint8_t>(digest[index]) == expected[index]);
    }
}

TEST_CASE("The MIRACL big-number byte bridge preserves fixed-width values", "[miracl_core_interface][big]")
{
    std::array<char, 48> input{};
    for(std::size_t index = 0; index < input.size(); ++index)
    {
        input[index] = static_cast<char>(index + 1);
    }
    miracl_core::big value{};
    std::array<char, input.size()> output{};

    miracl_core::from_bytes(value, input.data());
    miracl_core::to_bytes(output.data(), value);

    CHECK(output == input);
}
