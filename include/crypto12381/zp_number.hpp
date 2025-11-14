#ifndef CRYPTO12381_ZP_NUMBER_HPP
#define CRYPTO12381_ZP_NUMBER_HPP

#include <stdexcept>
#include <span>
#include <limits>
#include <vector>

#include <miracl-core/bls_BLS12381.h>
#include <miracl-core/randapi.h>

#include "interface.hpp"
#include "set.hpp"
#include "constant.hpp"
#include "chunk_range.hpp"
#include "data_access.hpp"
#include "random.hpp"

namespace crypto12381 
{
    using chunk_t = std::int64_t;

    static constexpr size_t p_bits = 384;
    static constexpr size_t p_size = p_bits / std::numeric_limits<unsigned char>::digits;

    template<typename T>
    concept Zp_element = element_of<T, Zp>;
}

namespace crypto12381::detail
{
    struct Zp_except_identity_t{};
    
    constexpr Zp_except_identity_t operator*(Zp_t) noexcept
    {
        return {};
    }

    template<typename T>
    consteval bool contains(constant_t<Zp_t{}>, std::type_identity<T>) noexcept
    {
        return requires(T&& t)
        {
            t.Zp_number();
        };
    }

    inline constexpr size_t chunke_bits = sizeof(size_t) * std::numeric_limits<unsigned char>::digits;
    inline constexpr size_t base_bits = 58uz;
    inline constexpr chunk_t base_mask = ((chunk_t)1 << (base_bits + 1)) - 1;
    inline constexpr size_t rest_bits = chunke_bits - base_bits;
    inline constexpr chunk_t chunk_max_limit = ((chunk_t)1 << (rest_bits - 1)) - 1;
    inline constexpr chunk_t chunk_min_limit = -chunk_max_limit;
    
    inline constexpr size_t n_chunks = 7uz;
    inline constexpr size_t bytes_size = n_chunks * sizeof(chunk_t);
    inline constexpr size_t head_bits = n_chunks * base_bits - p_bits + rest_bits;
    inline constexpr chunk_t head_max_limit = ((chunk_t)1 << (head_bits - 1)) - 1;
    inline constexpr chunk_t head_min_limit = -head_max_limit;

    
    inline constexpr size_t n_chunks2 = n_chunks * 2;
    inline constexpr size_t bytes_size2 = bytes_size * 2;
    inline constexpr size_t head_bits2 = n_chunks2 * base_bits - p_bits * 2 + rest_bits;
    inline constexpr chunk_t head_max_limit2 = ((chunk_t)1 << (head_bits2 - 1)) - 1;
    inline constexpr chunk_t head_min_limit2 = -head_max_limit2;

    template<std::integral T>
    constexpr T sign(T x)
    {
        if(x > 0)
        {
            return (T)1;
        }
        else if(x < 0)
        {
            return (T)-1;
        }
        else
        {
            return 0;
        }
    }

    inline constexpr ChunkRange default_range{ 0, 1 };
    inline constexpr ChunkRange rest_range_extrem{ head_min_limit, head_max_limit };
    inline constexpr ChunkRange head_range_extrem{ head_min_limit, head_max_limit };
    inline constexpr ChunkRange head_range_extrem2{ head_min_limit2, head_max_limit2 };

    template<ChunkRange Head = default_range, ChunkRange RestRange = default_range>
    class ZpNumber;

    template<ChunkRange Head = default_range, ChunkRange Rest = default_range>
    class ZpNumber2;
    
    struct ZpNumberData
    {
        chunk_t data[n_chunks];

        constexpr operator chunk_t*()
        {
            return data;
        } 

        template<class Self>
        constexpr decltype(auto) operator[](this Self&& self, size_t i) noexcept
        {
            return std::forward_like<Self>(self.data)[i];
        }

        friend constexpr bool operator==(const ZpNumberData&, const ZpNumberData&) = default;
    };
    
    inline constexpr ZpNumberData p_data = { 
        0x3FFFFFF00000001L,0x36900BFFF96FFBFL,0x180809A1D80553BL,0x14CA675F520CCE7L,0x73EDA7L,0x0L,0x0L 
    };

    constexpr ZpNumberData& p() noexcept
    {
        thread_local constinit auto p = p_data;
        return p;
    }

    constexpr ZpNumberData& prev_p() noexcept
    {
        thread_local constinit auto prev_p = [](){ 
            auto prev_p = p_data;
            --prev_p[0];
            return prev_p;
        }();
        
        return prev_p;
    }

    constexpr ZpNumberData& invp2m() noexcept
    {
        thread_local auto invp2m = [](){
            ZpNumberData invp2m;

            BLS12381_BIG::DBIG r{};
            BLS12381_BIG::BIG_one(r);
            BLS12381_BIG::BIG_dshl(r, p_bits);
            
            BLS12381_BIG::BIG_ddiv(invp2m, r, p());
            BLS12381_BIG::BIG_inc(invp2m, 1);
            BLS12381_BIG::BIG_norm(invp2m);

            return invp2m;
        }();

        return invp2m;
    }

    struct ZpNumber2Data
    {
        chunk_t chunks[n_chunks2];

        constexpr operator chunk_t*()
        {
            return chunks;
        } 

        template<class Self>
        constexpr decltype(auto) operator[](this Self&& self, size_t i) noexcept
        {
            return std::forward_like<Self>(self.chunks)[i];
        }

        friend constexpr bool operator==(const ZpNumber2Data&, const ZpNumber2Data&) = default;
    };

    inline constexpr ZpNumber2Data p2n_data = { 
        0, 0, 0, 0, 0, 0, 0,
        0x3FFFFFF00000001L,0x36900BFFF96FFBFL,0x180809A1D80553BL,0x14CA675F520CCE7L,0x73EDA7L,0x0L,0x0L 
    };

    constexpr ZpNumber2Data& p2n() noexcept
    {
        thread_local constinit auto p2n = p2n_data;
        return p2n;
    }

    template<ChunkRange Head, ChunkRange Rest>
    class ZpNumber
    {
        friend DataAccessor;
        friend auto hash_to(hash_state&& state, Zp_t) noexcept;
    public:
        constexpr ZpNumber(unsigned int value) noexcept requires(Rest.contains(default_range))
        : data_{ value } 
        {}

        constexpr explicit ZpNumber(serialized_view<Zp> bytes) requires(Rest.contains(default_range))
        {
            serialized_field<Zp> buffer;
            std::memcpy(buffer.data(), bytes.data(), serialized_size<Zp>);
            BLS12381_BIG::BIG_fromBytes(data_, buffer.data());
            if(BLS12381_BIG::BIG_comp(data_, p()) >= 0)
            {
                throw std::runtime_error{ "Parse to Zp number over range." };
            }
        }

        void serialize(std::span<char, serialized_size<Zp>> bytes) const noexcept
        {
            BLS12381_BIG::BIG_toBytes(bytes.data(), auto{ data_ });
        }

        static constexpr ZpNumber<Head, Rest> select(RandomEngine& random_engine)
        {
            const auto rng = (core::csprng*)random_engine.impl();
            ZpNumber<Head, Rest> result;
            BLS12381_BIG::BIG_randomnum(result.data_, p(), rng);
            return result;
        }

        static constexpr ZpNumber<Head, Rest> select_except0(RandomEngine& random_engine)
        {
            const auto rng = (core::csprng*)random_engine.impl();
            ZpNumber<Head, Rest> result;
            BLS12381_BIG::BIG_randomnum(result.data_, prev_p(), rng);
            BLS12381_BIG::BIG_inc(result.data_, 1);
            BLS12381_BIG::BIG_norm(result.data_);
            return result;
        }

        template<typename Self>
        constexpr decltype(auto) Zp_number(this Self&& self)
        {
            if constexpr(std::is_const_v<std::remove_reference_t<Self>>)
            {
                return ZpNumber{ std::forward<Self>(self) };
            }
            else
            {
                return std::forward<Self>(self);
            }
        }

        constexpr ZpNumber<Head> normalize_rests() const
        {
            auto result = data.create<ZpNumber<Head>>();
            result.data_[0] = 0;
            for(size_t i = 0; i < n_chunks - 1; ++i)
            {
                result.data_[i] += data_[i] & base_mask;
                result.data_[i + 1] = data_[i] >> base_bits;
            }
            return result;
        }

        constexpr ZpNumber<> normalize() const
        {
            auto result = data.create<ZpNumber<>>();
            auto& x = data(result);
            x = data_;

            BLS12381_BIG::DBIG dbig;
            BLS12381_BIG::BIG_mul(dbig, x, invp2m());

            BLS12381_BIG::BIG low_part;
            BLS12381_BIG::BIG high_part;
            BLS12381_BIG::BIG_split(high_part, low_part, dbig, p_bits);

            BLS12381_BIG::BIG_mul(dbig, high_part, p());

            BLS12381_BIG::BIG_sub(x, x, dbig);
            BLS12381_BIG::BIG_norm(x);

            if(BLS12381_BIG::BIG_comp(x, p()) == 1)
            {
                BLS12381_BIG::BIG_sub(x, x, p());
                BLS12381_BIG::BIG_norm(x);
            }

            return result;
        }

        void show() const
        {
            if constexpr(default_range.contains(Head))
            {
                BLS12381_BIG::BIG_output(auto{ data_ });
            }
            else
            {
                BLS12381_BIG::BIG_output(data(normalize()));
            }
        }

        friend constexpr auto operator-(const ZpNumber& self) noexcept
        {
            constexpr auto head = ChunkRange{ Head.max - 1, Head.max } - Head;
            constexpr auto rest = default_range - Rest;
            if constexpr(not head_range_extrem.contains(head))
            {
                return -self.normalize();
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return -self.normalize_rests();
            }
            else
            {
                static constinit auto np = ZpNumber::get_np<Head.max>();

                auto result = data.create<ZpNumber<head, rest>>();
                for(size_t i = 0; i < n_chunks; ++i)
                {
                    data(result)[i] = data(np)[i] - self.data_[i];
                }
                return result;
            }
        }

        friend constexpr auto inverse(const ZpNumber& self) noexcept
        {
            auto result = data.create<ZpNumber<>>(self.data_);
            BLS12381_BIG::BIG_invmodp(data(result), data(result), p());
            return result;
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator+(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            constexpr auto head = Head + RHead;
            constexpr auto rest = Rest + RRest;
            if constexpr(not head_range_extrem.contains(head))
            {
                return l.normalize() + r.normalize();
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return l.normalize_rests() + r.normalize_rests();
            }
            else
            {
                auto result = data.create<ZpNumber<head, rest>>();
                for(size_t i = 0; i < n_chunks; ++i)
                {
                    data(result)[i] = l.data_[i] + data(r)[i];
                }
                return result;
            }
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator-(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return l + -r;
        }

        template<std::integral auto Value>
        friend constexpr auto operator*(const ZpNumber& self, constant_t<Value>) noexcept
        {
            if constexpr(std::signed_integral<decltype(Value)>)
            {
                static_assert((chunk_t)Value >= chunk_min_limit && (chunk_t)Value <= chunk_max_limit);
            }
            else
            {
                static_assert(Value <= (size_t)std::numeric_limits<chunk_t>::max());
                static_assert((chunk_t)Value >= chunk_min_limit && (chunk_t)Value <= chunk_max_limit);
            }

            constexpr auto head = Head * constant_t<Value>{};
            constexpr auto rest = Rest * constant_t<Value>{};
            if constexpr(not head_range_extrem.contains(head))
            {
                return self.normalize() * constant_t<Value>{};
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return self.normalize_rests() * constant_t<Value>{};
            }
            else
            {
                auto result = data.create<ZpNumber<head, rest>>();
                for(size_t i = 0; i < n_chunks; ++i)
                {
                    data(result)[i] = self.data_[i] * Value;
                }
                return result;
            }
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator*(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            constexpr auto head = Head * RHead;
            static_assert(head_range_extrem2.contains(head), "head overflow");
            auto result = data.create<ZpNumber2<head>>();
            BLS12381_BIG::BIG_mul(data(result), auto{ l.data_ }, data(auto{ r }));
            return result;
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr bool operator==(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return data(l.normalize()) == data(r.normalize());
        }

    private:
        constexpr ZpNumber() noexcept = default;

        template<size_t N>
        static constexpr ZpNumber<> get_np() noexcept
        {
            return (data.create<ZpNumber<>>(p_data) * constant_t<N>{}).normalize_rests();
        }

        ZpNumberData data_;
    };

    template<ChunkRange Head, ChunkRange Rest>
    class ZpNumber2
    {
        friend DataAccessor;
    public:
        constexpr ZpNumber<> Zp_number() const
        {
            return normalize();
        }

        constexpr ZpNumber2<Head> normalize_rests() const
        {
            auto result = data.create<ZpNumber2<Head>>();
            result.data_[0] = 0;
            for(size_t i = 0; i < n_chunks2 - 1; ++i)
            {
                result.data_[i] += data_[i] & base_mask;
                result.data_[i + 1] = data_[i] >> base_bits;
            }
            return result;
        }

        constexpr ZpNumber<> normalize() const
        {
            auto result = data.create<ZpNumber<>>();
            BLS12381_BIG::BIG_dmod(data(result), auto{ data_ }, p());
            return result;
        }

        void show() const
        {
            BLS12381_BIG::BIG_output(data(normalize()));
        }

        constexpr auto operator-() const
        {
            constexpr auto head = ChunkRange{ Head.max - 1, Head.max } - Head;
            constexpr auto rest = default_range - Rest;
            if constexpr(not head_range_extrem2.contains(head))
            {
                return -normalize();
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return -normalize_rests();
            }
            else
            {
                constexpr auto np2n = get_np2n<Head.max>();

                auto result = data.create<ZpNumber2<head, rest>>();
                for(size_t i = 0; i < n_chunks2; ++i)
                {
                    data(result)[i] = data(np2n)[i] - data_[i];
                }
                return result;
            }
        }

        friend constexpr ZpNumber<> inverse(const ZpNumber2& self) noexcept
        {
            return inverse(self.normalize());
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator+(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            constexpr auto head = Head + RHead;
            constexpr auto rest = Rest + RRest;
            if constexpr(not head_range_extrem2.contains(head))
            {
                return l.normalize() + r.normalize();
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return l.normalize_rests() + r.normalize_rests();
            }
            else
            {
                auto result = data.create<ZpNumber2<head, rest>>();
                for(size_t i = 0; i < n_chunks2; ++i)
                {
                    data(result)[i] = l.data_[i] + data(r)[i];
                }
                return result;
            }
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator+(const ZpNumber2& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            constexpr auto head = Head + ChunkRange{ sign(RHead.min), sign(RHead.max) };
            constexpr auto rest = Rest + RRest;
            if constexpr(not head_range_extrem2.contains(head))
            {
                return l.normalize() + r.normalize();
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return l.normalize_rests() + r.normalize_rests();
            }
            else
            {
                auto result = data.create<ZpNumber2<head, rest>>();
                for(size_t i = 0; i < n_chunks; ++i)
                {
                    data(result)[i] = l.data_[i] + data(r)[i];
                }
                for(size_t i = n_chunks; i < n_chunks2; ++i)
                {
                    data(result)[i] = l.data_[i];
                }
                return result;
            }
        }

        template<ChunkRange LHead, ChunkRange LRest>
        friend constexpr auto operator+(const ZpNumber<LHead, LRest>& l, const ZpNumber2& r) noexcept
        {
            return r + l;
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator-(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            return l + -r;
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator-(const ZpNumber2& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return l + -r;
        }

        template<ChunkRange LHead, ChunkRange LRest>
        friend constexpr auto operator-(const ZpNumber<LHead, LRest>& l, const ZpNumber2& r) noexcept
        {
            return l + -r;
        }

        template<std::integral auto Value>
        friend constexpr auto operator*(const ZpNumber2& self, constant_t<Value>) noexcept
        {
            if constexpr(std::signed_integral<decltype(Value)>)
            {
                static_assert((chunk_t)Value >= chunk_min_limit && (chunk_t)Value <= chunk_max_limit);
            }
            else
            {
                static_assert(Value <= (size_t)std::numeric_limits<chunk_t>::max());
                static_assert((chunk_t)Value >= chunk_min_limit && (chunk_t)Value <= chunk_max_limit);
            }

            constexpr auto head = Head * constant_t<Value>{};
            constexpr auto rest = Rest * constant_t<Value>{};
            if constexpr(not head_range_extrem.contains(head))
            {
                return self.normalize() * constant_t<Value>{};
            }
            else if constexpr(not rest_range_extrem.contains(rest))
            {
                return self.normalize_rests() * constant_t<Value>{};
            }
            else
            {
                auto result = data.create<ZpNumber2<head, rest>>();
                for(size_t i = 0; i < n_chunks2; ++i)
                {
                    data(result)[i] = self.data_[i] * Value;
                }
                return result;
            }
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator*(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            return l.normalize() * r.normalize();
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator*(const ZpNumber2& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return l.normalize() * r;
        }

        template<ChunkRange LHead, ChunkRange LRest>
        friend constexpr auto operator*(const ZpNumber<LHead, LRest>& l, const ZpNumber2& r) noexcept
        {
            return l * r.normalize();
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr bool operator==(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            return data(l.normalize()) == data(r.normalize());
        }

    private:
        constexpr ZpNumber2() noexcept = default;

        template<size_t N>
        static consteval ZpNumber2<> get_np2n()
        {
            return (data.create<ZpNumber2<>>(p2n_data) * constant_t<N>{}).normalize_rests();
        }

        ZpNumber2Data data_;
    };

    constexpr auto select_in(constant_t<Zp>, RandomEngine& random) noexcept
    {
        return detail::ZpNumber<>::select(random);
    }

    constexpr auto select_in(constant_t<*Zp>, RandomEngine& random) noexcept
    {
        return detail::ZpNumber<>::select_except0(random);
    }

    template<typename T>
    consteval bool contains(constant_t<*Zp>, std::type_identity<T>) noexcept
    {
        return false;
    }

    constexpr auto parse(constant_t<Zp>, std::span<const char, serialized_size<Zp>> bytes)
    {
        return detail::ZpNumber<>{ bytes };
    }

    template<Zp_element T>
    constexpr void serialize_to(std::span<char, serialized_size<Zp>> bytes, T&& t)
    {
        std::forward<T>(t).Zp_number().serialize(bytes);
    }
    
    constexpr auto encode_to(constant_t<Zp>, std::span<const char> message)
    {
        // size of units splited form message
        // 248bits, a number smaller then 255bits(bit count of p)
        constexpr size_t unit_size = 31uz;
        std::vector<detail::ZpNumber<>> result;
        result.reserve((message.size() + unit_size - 1) / unit_size);
        
        serialized_field<Zp> buffer{};
        // set the 249th bit to avoid 0(some cryptographic algorithms require message components to be non-zero)
        buffer[buffer.size() - unit_size - 1] = 1;
        for(size_t i = 0; i < message.size() / unit_size; ++i)
        {
            
            std::memcpy(buffer.data() + (buffer.size() - unit_size), message.data() + unit_size * i, unit_size);
            result.emplace_back(crypto12381::parse<Zp>(buffer));
        }
        if(size_t rest = message.size() % unit_size)
        {
            buffer = {};
            buffer[buffer.size() - unit_size - 1] = 1;
            std::memcpy(buffer.data() + (buffer.size() - unit_size), message.data() + message.size() - rest, rest);
            result.emplace_back(crypto12381::parse<Zp>(buffer));
        }

        return result;
    }

    inline auto hash_to(hash_state&& state, Zp_t) noexcept
    {
        char hash_bytes[hash_state::hash_size];
        std::move(state).to(hash_bytes);
        BLS12381_BIG::DBIG dbig;
        BLS12381_BIG::BIG_dfromBytesLen(dbig, hash_bytes, hash_state::hash_size);
        ZpNumber<> result;
        BLS12381_BIG::BIG_ctdmod(result.data_, dbig, p(), hash_state::hash_size * 8 - 255);
        return result;
    }
}

#endif