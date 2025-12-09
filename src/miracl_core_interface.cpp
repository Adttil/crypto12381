#include <miracl-core/bls_BLS12381.h>
#include <miracl-core/randapi.h>

#include <crypto12381/miracl_core_interface.hpp>

using namespace core;
using namespace BLS12381;
using namespace BLS12381_BIG;

namespace crypto12381::detail::miracl_core
{
    void sha3_init(sha3_state& state, int output_size) noexcept
    {
        SHA3_init((sha3*)&state, output_size);
    }

    void sha3_process(sha3_state& state, int byte) noexcept
    {
        SHA3_process((sha3*)&state, byte);
    }

    void sha3_hash(sha3_state& state, char* buffer) noexcept
    {
        SHA3_hash((sha3*)&state, buffer);
    }
}

namespace crypto12381::detail::miracl_core
{
    void shift_left(big2& object, int n_bits) noexcept
    {
        BIG_dshl(object, n_bits);
    }

    void from_bytes(big& result, const char* bytes) noexcept
    {
        BIG_fromBytes(result, bytes);
    }

    void divide(big& result, big2& l, const big& r) noexcept
    {
        BIG_ddiv(result, l, r);
    }

    void increase(big& object, int value) noexcept
    {
        BIG_inc(object, value);
    }

    chunk_t normalize(big& object) noexcept
    {
        return BIG_norm(object);
    }

    int compare(const big& l, const big& r) noexcept
    {
        return BIG_comp(l, r);
    }

    void to_bytes(char* result, const big& value) noexcept
    {
        BIG_toBytes(result, value);
    }

    void random_in(big& result, const big& modulus, RandomEngine& random) noexcept
    {
        const auto rng = (core::csprng*)random.impl();
        BIG_randomnum(result, modulus, rng);
    }

    void multiply(big2& result, const big& l, const big& r) noexcept
    {
        BIG_mul(result, l, r);
    }

    chunk_t split(big& high_part, big& low_part, const big2& value, int position) noexcept
    {
        return BIG_split(high_part, low_part, value, position);
    }

    void mod_negate(big& result, const big& value, const big& modulus) noexcept
    {
        BIG_modneg(result, value, modulus);
    }

    void mod_inverse(big& result, big& value, const big& modulus) noexcept
    {
        BIG_invmodp(result, value, modulus);
    }

    void from_bytes(big2& result, const char* bytes, int size) noexcept
    {
        BIG_dfromBytesLen(result, bytes, size);
    }

    void fixed_time_mod(big& result, big2& value, const big& modulus, int n_bits_difference_max) noexcept
    {
        BIG_ctdmod(result, value, modulus, n_bits_difference_max);
    }

    void mod(big& result, big2& value, const big& modulus) noexcept
    {
        BIG_dmod(result, value, modulus);
    }
}

namespace crypto12381::detail::miracl_core
{
    int from_bytes(point1& result, bytes_view& bytes) noexcept
    {
        return ECP_fromOctet((ECP*)&result, (octet*)&bytes);
    }

    void to_bytes(bytes_view& result, point1& point, bool compressed) noexcept
    {
        ECP_toOctet((octet*)&result, (ECP*)&point, compressed);
    }

    void negate(point1& point) noexcept
    {
        ECP_neg((ECP*)&point);
    }

    void add(point1& object, point1& point) noexcept
    {
        ECP_add((ECP*)&object, (ECP*)&point);
    }

    void sub(point1& object, point1& point) noexcept
    {
        ECP_sub((ECP*)&object, (ECP*)&point);
    }

    int equal(point1& l, point1& r) noexcept
    {
        return ECP_equals((ECP*)&l, (ECP*)&r);
    }

    void residue(fp& result, const big& value) noexcept
    {
        FP_nres((FP*)&result, value);
    }

    void map_to_point(point1& result, const fp& value) noexcept
    {
        ECP_map2point((ECP*)&result, (const FP*)&value);
    }

    void multiply_cofactor(point1& object) noexcept
    {
        ECP_cfp((ECP*)&object);
    }    

    void get_infinity(point1& result) noexcept
    {
        ECP_inf((ECP*)&result);
    }

    int get_default_generator(point1& result) noexcept
    {
        return ECP_generator((ECP*)&result);
    }

    void multiply(point1& object, const big& value) noexcept
    {
        PAIR_G1mul((ECP*)&object, value);
    }

    void double_multiply(point1& p1, point1& p2, big& v1, big& v2) noexcept
    {
        ECP_mul2((ECP*)&p1, (ECP*)&p2, v1, v2);
    }
}

namespace crypto12381::detail::miracl_core 
{
    int from_bytes(point2& result, bytes_view& bytes) noexcept
    {
        return ECP2_fromOctet((ECP2*)&result, (octet*)&bytes);
    }

    void to_bytes(bytes_view& result, point2& point, bool compressed) noexcept
    {
        ECP2_toOctet((octet*)&result, (ECP2*)&point, compressed);
    }

    void multiply(point2& object, const big& value) noexcept
    {
        PAIR_G2mul((ECP2*)&object, value);
    }

    void negate(point2& point) noexcept
    {
        ECP2_neg((ECP2*)&point);
    }

    void add(point2& object, point2& point) noexcept
    {
        ECP2_add((ECP2*)&object, (ECP2*)&point);
    }

    void sub(point2& object, point2& point) noexcept
    {
        ECP2_sub((ECP2*)&object, (ECP2*)&point);
    }

    int equal(point2& l, point2& r) noexcept
    {
        return ECP2_equals((ECP2*)&l, (ECP2*)&r);
    }

    void get_infinity(point2& result) noexcept
    {
        ECP2_inf((ECP2*)&result);
    }

    //return 1 if successed else return 0
    int get_default_generator(point2& result) noexcept
    {
        return ECP2_generator((ECP2*)&result);
    }
}

namespace crypto12381::detail::miracl_core 
{
    void to_bytes(bytes_view& result, fp12& value) noexcept
    {
        FP12_toOctet((octet*)&result, (FP12*)&value);
    }

    void inverse(fp12& result, fp12& value) noexcept
    {
        FP12_inv((FP12*)&result, (FP12*)&value);
    }

    void multiply(fp12& result, fp12& value) noexcept
    {
        FP12_mul((FP12*)&result, (FP12*)&value);
    }

    void pow(fp12& result, fp12& base, const big& exponent) noexcept
    {
        FP12_pow((FP12*)&result, (FP12*)&base, exponent);
    }

    int equal(fp12& l, fp12& r) noexcept
    {
        return FP12_equals((FP12*)&l, (FP12*)&r);
    }

    void pair_ate(fp12& result, point2& p2, point1& p1) noexcept
    {
        PAIR_ate((FP12*)&result, (ECP2*)&p2, (ECP*)&p1);
    }

    void pair_final_exponentiation(fp12& object) noexcept
    {
        PAIR_fexp((FP12*)&object);
    }

    void pair_double_ate(fp12& result, point2& p2, point1& p1, point2& q2, point1& q1) noexcept
    {
        PAIR_double_ate((FP12*)&result, (ECP2*)&p2, (ECP*)&p1, (ECP2*)&q2, (ECP*)&q1);
    }
}