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
    
    //commitments of share of private attributes for each P
    //auto commitments = vss_of_private_attributes(pp, 3, 6, Prv, attrs, random);

    auto creds = cred_iss(pp, sk, 3, C, Pub, attrs, random);



    std::cout << "creds count: " << creds.D.size() << '\n';
}