#include <iostream>

#include <bbs.hpp>

using namespace crypto12381::bbs;

int main()
{
    auto random = create_random_engine("seed");

    auto pp = setup(16, random);
    auto keys = key_gen(pp, random);
    auto message = std::string{ "Hello, BBS!" };
    auto signature = sign(pp, keys.sk, message, random);
    bool success = verify(pp, keys.pk, message, signature);

    if(success)
    {
        std::cout << "success";
    }
    else
    {
        std::cout << "failed";
    }
}