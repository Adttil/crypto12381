#include <array>
#include <iostream>

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
        std::cout << "success";
    }
    else
    {
        std::cout << "failed";
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
        std::cout << "success";
    }
    else
    {
        std::cout << "failed";
    }
}

void sequentail_aggregate()
{
    auto random = ps::create_random_engine("seed");

    const auto as = ps::As::setup(random);
    const auto keys1 = as.key_gen(random);
    auto& [sk1, pk1] = keys1;
    const auto keys2 = as.key_gen(random);
    auto& [sk2, pk2] = keys2;

    std::string_view messages[] = { "message1", "m2" };
    std::span m = messages;
    auto empty = std::vector<ps::As::PublicKey>{};

    auto sig1 = as.sign(keys1, m[0], empty, m.subspan(0, 0), {}, random);

    auto sig2 = as.sign(keys2, m[1], std::vector{pk1}, m.subspan(0, 1), sig1, random);

    bool success = as.verify(std::vector{pk1, pk2}, m, sig2);
    
    if(success)
    {
        std::cout << "success";
    }
    else
    {
        std::cout << "failed";
    }
}

int main()
{
    single_message();
    multi_message();
    sequentail_aggregate();
}