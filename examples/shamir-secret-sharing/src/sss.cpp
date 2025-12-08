#include <crypto12381/crypto12381.hpp>
#include <sss.hpp>

namespace crypto12381::sss
{
    std::vector<serialized_field<Zp>> share(size_t t, size_t n, serialized_field<Zp> secret, RandomEngine& random) noexcept{
        auto s = parse<Zp>(secret);
        
        auto a = random-select_in<Zp>(t - 1) | materialize;

        return serialize(polynomial(x, s, a)) (x.in[1, n + 1]);
    }

    serialized_field<Zp> reconstruct(std::span<const size_t> indexes, std::span<const serialized_field<Zp>> shares) noexcept{
        auto t = indexes.size();
        auto x = make_Zp(i) (i.in(indexes)) | materialize;
        auto y = parse<Zp>(shares);

        auto λi = Π[j.in[t].except(i)] (-x[j] / (x[i] - x[j]));

        return serialize(Σ[t](y[i] * λi));
    }
} 