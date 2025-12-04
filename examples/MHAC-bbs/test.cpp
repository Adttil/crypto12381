#include <iostream>

#include <mhac_bbs.hpp>

using namespace crypto12381::mhac_bbs;

int main()
{
    auto random = create_random_engine("seed");

    auto pp = iss_setup(16uz, random);
        
}