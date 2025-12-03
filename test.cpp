#include <iostream>
#include <crypto12381/crypto12381.hpp>

using namespace crypto12381;

void pair_test()
{
    auto random = create_random_engine("this is a seed");

    auto g1 = random-select_in<*G1>;
    auto g2 = random-select_in<*G2>;

    auto [x, y] = random-select_in<Zp^2>;

    if(pair(g1^x, g2^y) == (pair(g1, g2)^(x * y)))
    {
        std::cout << "succeed";
    }
    else
    {
        std::cout << "failed";
    }
}

void parse_test()
{
    struct Data1 : serialized_field<Zp, G1^2>{};

    auto random = create_random_engine("this is a seed");
    auto [x, y, z] = random-select_in<Zp^3>;
    auto g = random-select_in<*G1>;
    auto Y = g^y;
    auto Z = g^z;

    Data1 data = serialize(x, g^y, g^z);
    
    auto [x1, Y1, Z1] = parse<Zp, G1, G1>(data);

    if(x == x1 && Y == Y1 && Z == Z1)
    {
        std::cout << "succeed";
    }
    else
    {
        std::cout << "failed";
    }
}

void hash_test()
{
    auto random = create_random_engine("this is a seed");
    
    auto [x, y, z] = random-select_in<Zp^3>;

    auto c1 = hash(x, y, z).to(Zp);
    auto c2 = hash(std::vector{ x, y, z }).to(Zp);

    if(c1 == c2)
    {
        std::cout << "succeed";
    }
    else
    {
        std::cout << "failed";
    }
}

int main()
{
    pair_test();
    parse_test();
    hash_test();

    return 0;
}