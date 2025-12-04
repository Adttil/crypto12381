#include <crypto12381/crypto12381.hpp>
#include <mhac_bbs.hpp>

namespace crypto12381::mhac_bbs
{
    IssSetupResult iss_setup(size_t m, RandomEngine& random) noexcept
    {
        auto pp = bbs::setup(m, random);
        auto keys = bbs::key_gen(pp, random);
        return IssSetupResult{ pp, keys };
    }
} 