#include <span>
#include <string>
#include <miracl-core/randapi.h>

#include <crypto12381/random.hpp>

namespace crypto12381
{
    struct RandomEngine::Impl : core::csprng
    {

    };

    RandomEngine::RandomEngine(std::span<const char> seed) noexcept
    {
        core::csprng* rng = impl_ = new RandomEngine::Impl;
        std::string buffer{ seed.begin(), seed.end() };
        core::octet buffer_view{
            .len = (int)buffer.size(), 
            .max = (int)buffer.size(), 
            .val = buffer.data()
        };
        core::CREATE_CSPRNG(rng, &buffer_view);
    }

    RandomEngine::~RandomEngine() noexcept
    {
        core::csprng* rng = impl_;
        core::KILL_CSPRNG(rng);
        delete impl_;
    }
}