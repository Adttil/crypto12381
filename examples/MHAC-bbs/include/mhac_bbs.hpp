#ifndef CRYPTO12381_TESTS_MHAC_BBS_MHAC_BBS_HPP
#define CRYPTO12381_TESTS_MHAC_BBS_MHAC_BBS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

#include "bbs.hpp"

namespace crypto12381::mhac_bbs
{
    using namespace crypto12381;

    using bbs::PublicParameters;
    using bbs::PublicKey;
    using bbs::PrivateKey;
    using bbs::Keys;

    struct IssSetupResult
    {
        PublicParameters pp;
        Keys keys;
    };

    IssSetupResult iss_setup(size_t m, RandomEngine& random) noexcept;

    // (A, e_share)
    struct Cred
    {
        serialized_field<G1> A;
        serialized_field<Zp> e_share;
    };

    std::vector<Cred> cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        size_t n, 
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    );

    std::vector<Cred> cred_pres(
        const PublicParameters& pp, 
        const PrivateKey& pk, 
        std::span<const Cred> creds,
        std::span<size_t> S,
        std::span<const serialized_field<Zp>> attributes,
        std::span<size_t> rev,
        RandomEngine& random
    );
}

#endif