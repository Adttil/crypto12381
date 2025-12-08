#include <iostream>
#include <ranges>
#include <sss.hpp>
#include <crypto12381/crypto12381.hpp>

using namespace crypto12381::sss;

int main()
{
    auto random = create_random_engine("seed");

    serialized_field<Zp> secret = serialize(random-select_in<Zp>);

    auto shares = sss::share(4, 6, secret, random);

    size_t indexes[4]{ 1, 3, 4, 6 };
    auto using_shares = indexes 
        | std::views::transform([&](size_t i){ return shares[i - 1]; }) 
        | std::ranges::to<std::vector>();
    
    auto reconstructed_secret = reconstruct(indexes, using_shares);

    if(secret == reconstructed_secret)
    {
        std::cout << "success\n";
    }
    else
    {
        std::cout << "failed\n";
    }
}