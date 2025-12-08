#include <iostream>

#include <mhac_bbs.hpp>

using namespace crypto12381::mhac_bbs;

int main()
{
    auto random = create_random_engine("seed");

    const auto [pp, keys] = iss_setup(4uz, random);
    const auto& [pk, sk] = keys;

    const serialized_field<Zp> attributes[4]{};

    auto creds = cred_iss(pp, sk, 4, 6, attributes, random);

    std::cout << "creds count: " << creds.size() << '\n';
}