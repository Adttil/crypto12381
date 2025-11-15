# Crypto12381
[![license](https://img.shields.io/github/license/Adttil/crypto12381.svg)](https://github.com/Adttil/crypto12381/blob/main/LICENSE.txt)
[![issues](https://img.shields.io/github/issues/Adttil/crypto12381.svg)](https://github.com/Adttil/crypto12381/issues)

Crypto12381 is an esay-to-use cryptographic library based on the elliptic curve BLS12-381.

Actually, it is a wrapper for a subset of the library [MIRACL-core](https://github.com/miracl/core), designed to make it easier to use.

# Overview
It is used as below:
```cpp
#include<print>
#include <crypto12381/crypto12381.hpp>

void pair_test()
{
    using namespace crypto12381;

    auto random = create_random_engine("this is a seed");

    auto g1 = random-select_in<*G1>;
    auto g2 = random-select_in<*G2>;

    auto [x, y] = random-select_in<Zp^2>;

    if(pair(g1^x, g2^y) == (pair(g1, g2)^(x * y)))
    {
        std::println("succeed");
    }
    else
    {
        std::println("failed");
    }
}
```
Using it feels like you're directly mirroring the formulas from the academic papers.

You can just read a signature example in [`example_ps.cpp`](example_ps.cpp).

# Random
You can create a random engine to select elements in groups.
```cpp
auto random = create_random_engine("this is a seed");

auto n1 = random-select_in<Zp>;// (1) select in Zp
auto n2 = random-select_in<*Zp>;// (2) select in Zp except 0
auto n3 = random-select_in<Zp>;// (3) select in Zp
auto n4 = random-select_in<*G1>;// (4) select in G1 except 1(select generator in G1)
auto [n51, n52, n53] = random-select_in<Zp^3>;// (5) select 3 number in Zp
auto [n61, n62] = random-select_in<*G2^2>;// (6) select 2 generator in G2

auto n7 = select_in<Zp>(random)；// (7) just same as (1)
auto n8 = select_in<*G2^2>(random)；// (8) just same as (6)
```

# Serialize
Prepare a `trivial-copyable` structure with proper size no matter how it defined.
```cpp
// definition(1)
struct Pack : serialized_field<Zp, G1^2>};
```
or
```cpp
// definition(2)
struct Pack
{
    serialized_field<Zp> x;
    serialized_field<G1> g1;
    serialized_field<G1> g2;
};
```
or
```cpp
// definition(3)
struct Pack
{
    char data[serialized_size<Zp> + serialized_size<G1^2>];
};
```

And Prepare the elements you want to serialize:
```cpp
auto x = random-select_in<Zp>;
auto [g1, g2] = random-select_in<*G1^2>;
```

Now you can serialze the elements to `pack` by several ways:
```cpp
Pack pack = serialize(x, g1, g2);
```
```cpp
auto pack = serialize(x, g1, g2).to<Pack>();
```
```cpp
Pack pack;
serialize(x, g1, g2).to(pack);
```
```cpp
// just for definition(2)
Pack pack;
serialize(x).to(pack.x);
serialize(g1).to(pack.g1);
serialize(g2).to(pack.g2);
```
```cpp
// just for definition(3)
Pack pack;
serialize(x, g1, g2).to(pack.data);
```

# Parse
For all the definition of `struct Pack` above, you can parse the `pack` by:
```cpp
auto[x, g1, g2] = parse<Zp, G1, G1>(pack);
```

# Hash
You can hash multiple elements to a number or a point:
```cpp
auto c1 = hash(x, g1, g2).to(Zp); // (1) hash to a number in Zp
auto c2 = hash(x, g1, g2).to(G1); // (2) hash to a point in G1
```
You can also append more elements after call hash
```cpp
auto c1 = (hash(x) | g1 | g2).to(Zp); // same as (1)
```
In fact, you can just write like this:
```cpp
auto c1 = (hash | x | g1 | g2).to(Zp); // same as (1)
```
You can also hash a variable number of elements by given a range of the elements:
```cpp 
auto elements = std::vector{ g1, g2 };
// push variable number of elements
for(size_t i = 0; i < n; ++i)
{
    elements.push_pack(random-select_in<*G1>);
}
// hash x and all elements to a number in Zp
auto c = hash(x, elements).to(Zp);
```