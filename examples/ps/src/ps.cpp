#include <crypto12381/crypto12381.hpp>
#include <ps.hpp>

namespace crypto12381::ps 
{
    Keys key_gen(RandomEngine& random)
    {
        auto g2 = random-select_in<*G2>;
        auto [x, y] = random-select_in<*Zp^2>;

        return { 
            serialize(x, y), // sk
            serialize(g2, g2^x, g2^y) // pk 
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

    Signature randomnize(const Signature& signature, RandomEngine& random)
    {
        auto [σ1, σ2] = parse<G1^2>(signature);
        auto r = random-select_in<*Zp>;
        return serialize(σ1^r, σ2^r);
    }

    KeysN key_gen(size_t n, RandomEngine& random)
    {
        auto g2 = random-select_in<*G2>;
        auto x = random-select_in<*Zp>;
        
        auto X2 = g2^x;

        KeysN keys;
        auto& [sk, pk] = keys;
        sk.x = serialize(x);
        pk.g2 = serialize(g2);
        pk.X2 = serialize(X2);

        sk.y.resize(n);
        pk.Y2.resize(n);
        for(size_t i = 0; i < n; ++i)
        {
            auto y = random-select_in<*Zp>;
            auto Y2 = g2^y;

            sk.y[i] = serialize(y);
            pk.Y2[i] = serialize(Y2);
        }
        return keys;
    }

    Signature sign(const PrivateKeyN& sk, std::span<const char> message, RandomEngine& random)
    {
        auto m = encode_to<Zp>(message);
        size_t n = m.size();
        if(n > sk.y.size())
        {
            throw std::runtime_error{ "message is too long" };
        }
        auto x = parse<Zp>(sk.x);
        auto y = parse<Zp>(sk.y);

        auto h = random-select_in<*G1>;

        return serialize(h, h^(x + Σ[n](y[i] * m[i])));
    };

    bool verify(const PublicKeyN& pk, std::span<const char> message, const Signature& signature)
    {
        auto m = encode_to<Zp>(message);
        size_t n = m.size();
        if(n > pk.Y2.size())
        {
            throw std::runtime_error{ "message is too long" };
        }
        auto g2 = parse<G2>(pk.g2);
        auto X2 = parse<G2>(pk.X2);
        auto Y2 = parse<G2>(pk.Y2);

        auto [σ1, σ2] = parse<G1, G1>(signature);

        return pair(σ1, X2 * Π[n](Y2[i] ^ m[i])) == pair(σ2, g2);
    }

    As As::setup(RandomEngine& random)
    {
        auto g1 = random-select_in<*G1>;
        auto g2 = random-select_in<*G2>;
        auto x = random-select_in<*Zp>;
        auto X1 = g1^x;
        auto X2 = g2^x;

        return { .pp = serialize(g1, X1, g2, X2) };
    }

    As::Keys As::key_gen(RandomEngine& random) const
    {
        auto [g1, X1, g2, X2] = parse<G1^2 | G2^2>(pp);

        auto y = random-select_in<Zp>;
        auto Y2 = g2^y;

        return {
            .sk = serialize(y),
            .pk = serialize(Y2)
        };
    }
    
    Signature As::sign_no_check(const PrivateKey& sk, std::span<const char> message, const Signature& signature, RandomEngine& random) const
    {
        auto m = hash(message).to(Zp);
        auto [g1, X1, g2, X2] = parse<G1^2 | G2^2>(pp);
        auto y = parse<Zp>(sk);
        auto [σ1, σ2] = parse<G1^2>(signature);

        auto t = random-select_in<Zp>;

        return serialize(σ1^t, (σ2 * pow(σ1, y * m))^t);
    }

    bool As::verify_impl(std::span<std::reference_wrapper<const PublicKey>> pks, std::span<std::span<const char>> messages, const Signature& signature) const
    {
        auto [g1, X1, g2, X2] = parse<G1^2 | G2^2>(pp);
        auto Y2 = parse<G2>(pks);
        auto r = messages.size();
        auto m = hash(subscript(messages, i)).to(Zp) (i.in[r]);        
        auto [σ1, σ2] = parse<G1^2>(signature);

        return pair(σ1, X2 * Π[r](Y2[i]^m[i])) == pair(σ2, g2);
    }
}