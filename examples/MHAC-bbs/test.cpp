#include <chrono>
#include <print>
#include <iostream>

#include <mhac_bbs.hpp>

using namespace crypto12381::mhac_bbs;

struct timer
{
    std::chrono::high_resolution_clock::time_point start_time;

    timer()
    {
        start_time = std::chrono::high_resolution_clock::now();
    }

    ~timer()
    {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        std::println("finish in {} μs", duration);
    }  
};

// mesure execution time for any function
template<auto Fn, typename...Args>
constexpr decltype(auto) timed(Args&&...args)
{
    timer t;
    return Fn(std::forward<Args>(args)...);
};

int main()
{
    auto random = create_random_engine("seed");

    std::cout << "setup...\n";
    const auto [pp, keys] = timed<iss_setup>(4uz, random);
    const auto& [pk, sk] = keys;

    const std::array<size_t, 2> Prv{ 0, 2 };
    const std::array<size_t, 2> Pub{ 1, 3 };

    std::cout << "generate attributes...\n";
    const auto attr_info = timed<generate_attributes>(pp, 3, 6, Prv, random);
    const auto& [pub_attrs, prv_attr_shares, C] = attr_info;

    std::cout << "cred issue...\n";
    const auto creds = timed<cred_iss>(pp, sk, 3, C, Pub, pub_attrs, random);

    const std::array<size_t, 3> S{ 0, 2, 5 };
    const std::array<size_t, 1> Rev{ 1 };
    std::cout << "cred present...\n";
    const auto pres = timed<cred_pres>(pp, creds, S, Rev, Prv, pub_attrs, prv_attr_shares, random);

    std::cout << "verify...\n";
    const bool success = timed<verify_pres>(pp, pk, Rev, Prv, pub_attrs, pres);
    
    if(success)
    {
        std::cout << "success\n";
    }
    else
    {
        std::cout << "failed\n";
    }
}