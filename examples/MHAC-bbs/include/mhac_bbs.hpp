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
}

#endif