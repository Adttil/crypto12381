#include <iostream>
#include <crypto12381/crypto12381.hpp>

using namespace crypto12381;

struct PrivateKey : serialized_field<Zp^2>{};

struct PublicKey : serialized_field<G2^3>{};

struct Keys
{
    PrivateKey sk;
    PublicKey pk;
};

struct Signature : serialized_field<G1^2>{};
    
Keys key_gen(RandomEngine& random)
{
    auto g2 = random-select_in<*G2>;
    auto [x, y] = random-select_in<*Zp^2>;
    return { 
        .sk = serialize(x, y),
        .pk = serialize(g2, g2^x, g2^y)
    };
}

Signature sign(const PrivateKey& sk, std::span<const char> message, RandomEngine& random)
{
    auto [x, y] = parse<Zp^2>(sk);
    auto m = hash(message).to(Zp);
    auto h = random-select_in<*G1>;
    return serialize(h, h^(x + y * m));
}

bool verify(const PublicKey& pk, std::span<const char> message, const Signature& signature)
{
    auto [g2, X2, Y2] = parse<G2^3>(pk);
    auto m = hash(message).to(Zp);
    auto [σ1, σ2] = parse<G1^2>(signature);
    return pair(σ1, X2 * (Y2^m)) == pair(σ2, g2);
}

int main()
{
    auto random = create_random_engine("this is a seed");

    auto [sk, pk] = key_gen(random);

    auto signature = sign(sk, "this is a message to sign", random);
    
    if(verify(pk, "this is a message to sign", signature))
    {
        std::cout << "pass";
    }
    else
    {
        std::cout << "reject";
    }
}