#ifndef CRYPTO12381_MIRACL_CORE_INTERFACE_HPP
#define CRYPTO12381_MIRACL_CORE_INTERFACE_HPP

#include "random.hpp"
#include <cstdint>

namespace crypto12381::detail::miracl_core
{
    struct sha3_state
    {
        int length;
        std::uint64_t S[25];
        int rate, len;
    };

    void sha3_init(sha3_state& state, int output_size) noexcept;

    void sha3_process(sha3_state& state, int byte) noexcept;

    void sha3_hash(sha3_state& state, char* buffer) noexcept;
}

namespace crypto12381::detail
{
    using chunk_t = std::int64_t;
    inline constexpr size_t n_chunks = 7uz;
    inline constexpr size_t n_chunks2 = n_chunks * 2;
}

namespace crypto12381::detail::miracl_core
{
    using big = chunk_t[n_chunks];
    using big2 = chunk_t[n_chunks2];

    void shift_left(big2& object, int n_bits) noexcept;

    void from_bytes(big& result, const char* bytes) noexcept;

    void divide(big& result, big2& l, const big& r) noexcept;

    void increase(big& object, int value) noexcept;

    chunk_t normalize(big& object) noexcept;

    //return 1 if l > r, return -1 if l < r, return 0 if l == r
    int compare(const big& l, const big& r) noexcept;

    void to_bytes(char* result, const big& value) noexcept;

    void random_in(big& result, const big& modulus, RandomEngine& random) noexcept;

    void multiply(big2& result, const big& l, const big& r) noexcept;

    chunk_t split(big& high_part, big& low_part, const big2& value, int position) noexcept;

    void mod_negate(big& result, const big& value, const big& modulus) noexcept;

    void mod_inverse(big& result, big& value, const big& modulus) noexcept;

    void from_bytes(big2& result, const char* bytes, int size) noexcept;

    void fixed_time_mod(big& result, big2& value, const big& modulus, int n_bits_difference_max) noexcept;

    void mod(big& result, big2& value, const big& modulus) noexcept;
}

namespace crypto12381::detail::miracl_core
{
    struct bytes_view
    {
        int   len;
        int   max;
        char* data;
    };

    struct fp
    {
        big g;
        std::int32_t xes;
    };

    struct point1
    {
        fp x;
        fp y;
        fp z;
    };

    //return 1 if successed else return 0
    int from_bytes(point1& result, bytes_view& bytes) noexcept;

    void to_bytes(bytes_view& result, point1& point, bool compressed) noexcept;

    void negate(point1& point) noexcept;

    // object = object + point
    void add(point1& object, point1& point) noexcept;

    //result = Σ(numbers[i] * points[i]) for i in [n]
    void sum_of_products(point1& result, int n, point1* points, const big* numbers) noexcept;

    // object = object - point
    void sub(point1& object, point1& point) noexcept;

    // return 1 if l == r else return 0
    int equal(point1& l, point1& r) noexcept;

    void residue(fp& result, const big& value) noexcept;

    void map_to_point(point1& result, const fp& value) noexcept;

    void multiply_cofactor(point1& object) noexcept;

    void get_infinity(point1& result) noexcept;

    //return 1 if successed else return 0
    int get_default_generator(point1& result) noexcept;

    // object = value * object
    void multiply(point1& object, const big& value) noexcept;

    // p1 = v1 * p1 + v2 * p2
    void double_multiply(point1& p1, point1& p2, big& v1, big& v2) noexcept;
}

namespace crypto12381::detail::miracl_core
{
    struct fp2
    {
        fp a;
        fp b;
    };

    struct point2
    {
        fp2 x;
        fp2 y;
        fp2 z;
    };

    //return 1 if successed else return 0
    int from_bytes(point2& result, bytes_view& bytes) noexcept;

    void to_bytes(bytes_view& result, point2& point, bool compressed) noexcept;

    // object = value * object
    void multiply(point2& object, const big& value) noexcept;

    void negate(point2& point) noexcept;

    // object = object + point
    void add(point2& object, point2& point) noexcept;

    // object = object - point
    void sub(point2& object, point2& point) noexcept;

    // return 1 if l == r else return 0
    int equal(point2& l, point2& r) noexcept;

    void get_infinity(point2& result) noexcept;

    //return 1 if successed else return 0
    int get_default_generator(point2& result) noexcept;
}

namespace crypto12381::detail::miracl_core
{
    struct fp4
    {
        fp2 a;
        fp2 b;
    };

    struct fp12
    {
        fp4 a;
        fp4 b;
        fp4 c;
        int type;
    };

    void from_bytes(fp12& result, bytes_view& bytes) noexcept;

    void to_bytes(bytes_view& result, fp12& value) noexcept;

    void inverse(fp12& result, fp12& value) noexcept;

    void multiply(fp12& result, fp12& value) noexcept;

    void pow(fp12& result, fp12& base, const big& exponent) noexcept;

    int equal(fp12& l, fp12& r) noexcept;

    void pair_ate(fp12& result, point2& p2, point1& p1) noexcept;

    void pair_final_exponentiation(fp12& object) noexcept;

    void pair_double_ate(fp12& result, point2& p2, point1& p1, point2& q2, point1& q1) noexcept;
}

#endif