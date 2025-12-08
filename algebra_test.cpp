#include <iostream>
#include <crypto12381/algebra.hpp>

using namespace crypto12381;

int main()
{
    static constexpr symbol<"x"> x;
    static constexpr symbol<"y"> y;

    static constexpr auto f = x + y - 1;

    static constexpr auto f2 = f(x = y + 3); //2y + 2

    constexpr auto range = f2(y.in[1, 3]);

    constexpr auto f2_1 = range[0];
    constexpr auto f2_2 = range[1];

    constexpr auto z = f2(y = 5);

    constexpr auto arr = std::array{ 1, 2, 3, 4, 5 } | algebraic;

    static constexpr symbol<"i"> i;

    constexpr auto rr = (arr[i] + arr[i + 1]) (i.in[0, x]) (x = 3) [2];

    //static constexpr symbol<"i"> i;

    auto arri = subscript(arr, i);

    constexpr auto s = arr[i](i.in[2u].except(x))(x = 1)[0];


    subscript(arr, 0);
    substitute(arri, i = 0);
    
    constexpr auto arr3 = (arr[4 - i])(i.in[0, 5])[1];

    constexpr auto ccc = arr[i](i.in[x])(x = 3)[1];

    //auto arr1 = arr[x](x.in[2u]);

    return 0;
}