#include <array>
#include <print>

#include <ps.hpp>

namespace ps = crypto12381::ps;

template<size_t N>
struct X
{
    static constexpr size_t n = N;
};

constexpr size_t foo(auto&& x)
{
    return x.n;
}

void single_message()
{
    auto random = ps::create_random_engine("seed");

    auto [sk, pk] = ps::key_gen(random);

    ps::serialized_field<ps::Zp> message{ };
    message[ps::serialized_size<ps::Zp> - 1] = 23;
    auto signature = ps::sign(sk, message, random);

    signature = ps::randomnize(signature, random);

    bool success = ps::verify(pk, message, signature);
    
    if(success)
    {
        std::println("success");
    }
    else
    {
        std::println("failed");
    }
}

void multi_message()
{
    auto random = ps::create_random_engine("seed");

    auto [sk, pk] = ps::key_gen(5, random);

    std::string_view message = "what a fuck, that is too short, hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

    auto signature = ps::sign(sk, message, random);

    signature = ps::randomnize(signature, random);

    bool success = ps::verify(pk, message, signature);
    
    if(success)
    {
        std::println("success");
    }
    else
    {
        std::println("failed");
    }
}

int main()
{
    single_message();
    multi_message();
}