#include <iostream>

#include <mhac_bbs.hpp>

using namespace crypto12381::mhac_bbs;

int main()
{
    auto random = create_random_engine("seed");

    const auto [pp, keys] = iss_setup(4uz, random);
    const auto& [pk, sk] = keys;

    const std::array<size_t, 2> Prv{ 0, 2 };
    const std::array<size_t, 2> Pub{ 1, 3 };

    const auto attr_info = generate_attributes(pp, 3, 6, Prv, random);
    const auto& [attrs, attr_shares, C] = attr_info;

    const auto creds = cred_iss(pp, sk, 3, C, Pub, attrs, random);

    const std::array<size_t, 3> S{ 0, 2, 5 };
    const std::array<size_t, 1> Rev{ 1 };
    const auto pres = cred_pres(pp, pk, creds, S, Rev, Prv, attrs, attr_shares, random);

    const bool success = verify_pres(pp, pk, Rev, Prv, attrs, pres);
    
    if(success)
    {
        std::cout << "success\n";
    }
    else
    {
        std::cout << "failed\n";
    }
}