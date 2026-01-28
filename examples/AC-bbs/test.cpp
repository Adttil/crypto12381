#include <array>
#include <chrono>
#include <print>

#include <AC-bbs.hpp>

namespace ac = crypto12381::ac_bbs;

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
    constexpr size_t n = 32;
    
    auto random = ac::create_random_engine("seed");

    auto keys = timed<ac::keygen>(n, random);
    auto&& [sk, pk] = keys;

    auto attributes = ac::generate_attributes(pk, n, random);

    auto sig = timed<ac::issue>(keys, attributes, random);

    constexpr size_t I[]{ 0, 3 };

    const auto& message = "";

    auto pres = timed<ac::pres>(message, attributes, sig, I, pk, random);

    try{
    bool success = timed<ac::verify>(message, attributes, I, pres, pk);

    if(success)
    {
        std::println("success");
    }
    else
    {
        std::println("failed");
    }
    }
    catch(std::exception& e)
    {
        std::println("{}", e.what());
    }
}