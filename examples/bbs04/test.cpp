#include <array>
#include <print>
#include <ranges>

#include <bbs.hpp>

namespace bbs = crypto12381::bbs04;

int main()
{
    auto random = bbs::create_random_engine("seed");

    auto [gpk, gmsk, gsk] = bbs::key_gen(4, random);

    std::span message = "hello bbs";

    auto signature = bbs::sign(gpk, gsk[2], message, random);

    if(bbs::verify(gpk, message, signature))
    {
        std::println("pass");
    }
    else
    {
        std::println("reject");
    }

    auto A = bbs::open(gmsk, signature);
    for(auto&&[i, gski] : gsk | std::views::enumerate)
    {
        if(std::memcmp(&A, &gski, sizeof(A)) == 0)
        {
            std::println("index: {}", i);
            break;
        }
    }
}