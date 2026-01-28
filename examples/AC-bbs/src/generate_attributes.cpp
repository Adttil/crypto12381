#include <crypto12381/crypto12381.hpp>
#include <AC-bbs.hpp>

namespace crypto12381::ac_bbs
{
    std::vector<serialized_field<Zp>> generate_attributes(const PublicKey& pk, size_t n, RandomEngine& random)
    {
        auto a = random-select_in<Zp>(n);
        return serialize(a[i]) (i.in[n]);
    }
}