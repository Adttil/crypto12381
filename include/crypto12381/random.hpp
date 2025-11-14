#ifndef CRYPTO12381_RANDOM_HPP
#define CRYPTO12381_RANDOM_HPP

#include <span>

namespace crypto12381 
{
    struct RandomEngine
    {
    public:
        constexpr const void* impl()
        {
            return impl_;
        }

        explicit RandomEngine(std::span<const char> seed) noexcept;

        ~RandomEngine() noexcept;
    private:
        struct Impl;
        
        Impl* impl_;
    };

    constexpr RandomEngine create_random_engine(std::span<const char> seed)
    {
        return RandomEngine{ seed };
    }
}

#endif