#ifndef CRYPTO12381_ZP_NUMBER_HPP
#define CRYPTO12381_ZP_NUMBER_HPP

#include <cstring>
#include <cmath>
#include <stdexcept>
#include <span>
#include <limits>
#include <vector>

#include "miracl_core_interface.hpp"

#include "general.hpp"
#include "interface.hpp"
#include "set.hpp"
#include "constant.hpp"
#include "chunk_range.hpp"
#include "data_access.hpp"
#include "random.hpp"

namespace crypto12381 
{
    template<typename T>
    concept Zp_element = element_of<T, Zp>;
}

namespace crypto12381::detail 
{
    inline constexpr ChunkRange default_range{ 0, 1 };

    template<ChunkRange Head = default_range, ChunkRange RestRange = default_range>
    class ZpNumber;

    using Zp_normalized_t = ZpNumber<>;
}

namespace crypto12381::detail::sets 
{
    template<typename T>
    consteval bool contains(constant_t<Zp_t{}>, std::type_identity<T>) noexcept
    {
        return std::convertible_to<T, Zp_normalized_t> && requires(T&& t)
        {
            t.Zp_number();
        };
    }
    
    struct Zp_except_identity_t{};
    
    constexpr Zp_except_identity_t operator*(Zp_t) noexcept
    {
        return {};
    }
}

namespace crypto12381::detail
{
    inline constexpr size_t p_bits = 384;
    inline constexpr size_t p_size = p_bits / std::numeric_limits<unsigned char>::digits;
    
    inline constexpr size_t chunke_bits = sizeof(size_t) * std::numeric_limits<unsigned char>::digits;
    inline constexpr size_t base_bits = 58uz;
    inline constexpr chunk_t base_mask = ((chunk_t)1 << (base_bits + 1)) - 1;
    inline constexpr size_t rest_bits = chunke_bits - base_bits;
    inline constexpr chunk_t chunk_max_limit = ((chunk_t)1 << (rest_bits - 1)) - 1;
    inline constexpr chunk_t chunk_min_limit = -chunk_max_limit;
    
    inline constexpr size_t bytes_size = n_chunks * sizeof(chunk_t);
    inline constexpr size_t head_bits = n_chunks * base_bits - p_bits + rest_bits;
    inline constexpr chunk_t head_max_limit = ((chunk_t)1 << (head_bits - 1)) - 1;
    inline constexpr chunk_t head_min_limit = -head_max_limit;

    
    inline constexpr size_t bytes_size2 = bytes_size * 2;
    inline constexpr size_t head_bits2 = n_chunks2 * base_bits - p_bits * 2 + rest_bits;
    inline constexpr chunk_t head_max_limit2 = ((chunk_t)1 << (head_bits2 - 1)) - 1;
    inline constexpr chunk_t head_min_limit2 = -head_max_limit2;

    
    inline constexpr ChunkRange rest_range_extrem{ head_min_limit, head_max_limit };
    inline constexpr ChunkRange head_range_extrem{ head_min_limit, head_max_limit };
    inline constexpr ChunkRange head_range_extrem2{ head_min_limit2, head_max_limit2 };

    template<ChunkRange Head = default_range, ChunkRange Rest = default_range>
    class ZpNumber2;
    
    struct ZpNumberData
    {
        miracl_core::big chunks;

        constexpr operator miracl_core::big&() noexcept
        {
            return chunks;
        } 

        constexpr operator const miracl_core::big&()const noexcept
        {
            return chunks;
        } 

        template<class Self>
        constexpr decltype(auto) operator[](this Self&& self, size_t i) noexcept
        {
            return std::forward_like<Self>(self.chunks)[i];
        }

        friend constexpr bool operator==(const ZpNumberData&, const ZpNumberData&) = default;
    };
    
    inline constexpr ZpNumberData p_data = { 
        0x3FFFFFF00000001L,0x36900BFFF96FFBFL,0x180809A1D80553BL,0x14CA675F520CCE7L,0x73EDA7L,0x0L,0x0L 
    };

    inline constexpr ZpNumberData prev_p_data = [](){ 
        auto prev_p = p_data;
        --prev_p[0];
        return prev_p;
    }();

    constexpr const ZpNumberData& invp2m() noexcept
    {
        thread_local const auto invp2m = [](){
            ZpNumberData invp2m;

            miracl_core::big2 r{ 1 };
            miracl_core::shift_left(r, p_bits);
            miracl_core::divide(invp2m, r, p_data);
            miracl_core::increase(invp2m, 1);
            miracl_core::normalize(invp2m);

            return invp2m;
        }();

        return invp2m;
    }

    struct ZpNumber2Data
    {
        miracl_core::big2 chunks;

        constexpr operator miracl_core::big2&() noexcept
        {
            return chunks;
        } 

        constexpr operator const miracl_core::big2&()const noexcept
        {
            return chunks;
        } 

        ZpNumber2Data& operator=(const ZpNumberData& data) noexcept
        {
            *this = ZpNumber2Data{};
            for(size_t i = 0; i < n_chunks; ++i)
            {
                chunks[i] = data[i];
            }
            return *this;
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

    template<ChunkRange Head, ChunkRange Rest>
    class ZpNumber
    {
        friend DataAccessor;
    public:
        constexpr ZpNumber(unsigned int value) noexcept requires(Rest.contains(default_range))
        : data_{ value } 
        {}

        constexpr explicit ZpNumber(serialized_view<Zp> bytes) requires(Rest.contains(default_range))
        {
            miracl_core::from_bytes(data_, bytes.data());
            if(miracl_core::compare(data_, p_data) >= 0)
            {
                throw std::runtime_error{ "Parse to Zp number over range." };
            }
        }

        constexpr ZpNumber(const ZpNumber&) = default;
        constexpr ZpNumber(ZpNumber&&) = default;

        void serialize(std::span<char, serialized_size<Zp>> bytes) const noexcept
        {
            miracl_core::to_bytes(bytes.data(), data_);
        }

        static constexpr ZpNumber<Head, Rest> select(RandomEngine& random_engine) noexcept
        {
            ZpNumber<Head, Rest> result;
            miracl_core::random_in(result.data_, p_data, random_engine);
            return result;
        }

        static constexpr ZpNumber<Head, Rest> select_except0(RandomEngine& random_engine) noexcept
        {
            ZpNumber<Head, Rest> result;
            miracl_core::random_in(result.data_, prev_p_data, random_engine);
            miracl_core::increase(result.data_, 1);
            miracl_core::normalize(result.data_);
            return result;
        }

        template<typename Self>
        requires (not std::same_as<ZpNumber, Zp_normalized_t>)
        constexpr operator Zp_normalized_t(this Self&& self) noexcept
        {
            return std::forward<Self>(self).normalize();
        }

        template<typename Self>
        constexpr decltype(auto) Zp_number(this Self&& self) noexcept
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

        constexpr ZpNumber<Head> normalize_rests() const noexcept
        {
            auto result = data.create<ZpNumber<Head>>();
            data(result)[0] = 0;
            for(size_t i = 0; i < n_chunks - 1; ++i)
            {
                data(result)[i] += data_[i] & base_mask;
                data(result)[i + 1] = data_[i] >> base_bits;
            }
            return result;
        }

        constexpr ZpNumber<> normalize() const noexcept
        {
            auto result = data.create<ZpNumber<>>();
            auto& x = data(result);
            x = data_;

            miracl_core::big2 dbig;
            miracl_core::multiply(dbig, x, invp2m());

            miracl_core::big low_part;
            miracl_core::big high_part;
            miracl_core::split(high_part, low_part, dbig, p_bits);

            miracl_core::multiply(dbig, high_part, p_data);

            for(size_t i = 0; i < n_chunks; ++i)
            {
                x[i] -= dbig[i];
            }
            miracl_core::normalize(x);

            if(miracl_core::compare(x, p_data) == 1)
            {
                for(size_t i = 0; i < n_chunks; ++i)
                {
                    x[i] -= p_data[i];
                }
                miracl_core::normalize(x);
            }

            return result;
        }

        // void show() const
        // {
        //     if constexpr(default_range.contains(Head))
        //     {
        //         BLS12381_BIG::BIG_output(auto{ data_ });
        //     }
        //     else
        //     {
        //         BLS12381_BIG::BIG_output(data(normalize()));
        //     }
        // }

        friend constexpr auto operator-(const ZpNumber& self) noexcept
        {
            auto result = data.create<ZpNumber<>>();
            miracl_core::mod_negate(data(result), self.data_, p_data);
            return result;

            // Error in some case
            // constexpr auto head = ChunkRange{ Head.max - 1, Head.max } - Head;
            // constexpr auto rest = default_range - Rest;
            // if constexpr(not head_range_extrem.contains(head))
            // {
            //     return -self.normalize();
            // }
            // else if constexpr(not rest_range_extrem.contains(rest))
            // {
            //     return -self.normalize_rests();
            // }
            // else
            // {
            //     static constinit auto np = ZpNumber::get_np<Head.max>();

            //     auto result = data.create<ZpNumber<head, rest>>();
            //     for(size_t i = 0; i < n_chunks; ++i)
            //     {
            //         data(result)[i] = data(np)[i] - self.data_[i];
            //     }
            //     return result;
            // }
        }

        friend constexpr auto inverse(const ZpNumber& self) noexcept
        {
            auto result = data.create<ZpNumber<>>(self.data_);
            miracl_core::mod_inverse(data(result), data(result), p_data);
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
            miracl_core::multiply(data(result), l.data_ , data(r));
            return result;
        }

         template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator/(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return l * inverse(r);
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr bool operator==(const ZpNumber& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return miracl_core::compare(data(l.normalize()), data(r.normalize())) == 0;
        }

        static Zp_normalized_t from_hash(hash_state&& state) noexcept
        requires std::same_as<ZpNumber<>, Zp_normalized_t>
        {
            const auto hash_bytes = std::move(state).to();
            miracl_core::big2 dbig;
            miracl_core::from_bytes(dbig, hash_bytes.data(), hash_state::hash_size);
            Zp_normalized_t result;
            miracl_core::fixed_time_mod(result.data_, dbig, p_data, hash_state::hash_size * 8 - 255);
            return result;
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, ZpNumber>
        friend constexpr auto sum(std::type_identity<ZpNumber>, R&& r) 
        {
            if constexpr(Rest.min == 0 && Rest.max == 0)
            {
                return ZpNumber{};
            }
            else if(std::ranges::size(r) == 0)
            {
                return data.create<ZpNumber<>>();
            }
            else
            {
                constexpr size_t n = head_range_extrem / Head - 1;
                constexpr size_t m = rest_range_extrem / Rest - 1;
                if constexpr(n == 0)
                {
                    return sum(constant<Zp>, std::forward<R>(r) 
                    | std::views::transform([]<typename E>(E&& e){ 
                        return std::forward<E>(e).normalize(); 
                    }));
                }
                else if constexpr(m == 0)
                {
                    return sum(constant<Zp>, std::forward<R>(r)
                    | std::views::transform([]<typename E>(E&& e){
                        return std::forward<E>(e).normalize_rests(); 
                    }));
                }
                else
                {
                    auto result = data.create<ZpNumber<>>();
                    auto i = std::ranges::begin(r);
                    data(result) = data(*i);
                    size_t j = 0;
                    size_t k = 0;
                    for(++i; i != std::ranges::end(r); ++i)
                    {
                        data(result) = data(result + *i);
                        ++j;
                        ++k;
                        if(j == n)
                        {
                            data(result) = data(result.normalize());
                            j = 0;
                            k = 0;
                            continue;
                        }
                        if(k == n)
                        {
                            data(result) = data(result.normalize_rests());
                            k = 0;
                            continue;
                        }
                    }
                    if(j != 0)
                    {
                        data(result) = data(result.normalize());
                    }
                    else if(k != 0)
                    {
                        data(result) = data(result.normalize_rests());
                    }
                    return result;
                }
            }
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, ZpNumber>
        friend constexpr auto product(std::type_identity<ZpNumber>, R&& r) 
        {
            auto iter = std::ranges::begin(r);
            auto result = (*iter).Zp_number();
            auto& x = data(result);
            for(auto i = ++iter; i != std::ranges::end(r); ++i)
            {
                x = data((result * *i).Zp_number());
            }
            return result;
        }

    private:
        constexpr ZpNumber() noexcept = default;

        ZpNumber& operator=(const ZpNumber&) = default;
        ZpNumber& operator=(ZpNumber&&) = default;

        template<size_t N>
        static constexpr auto get_np() noexcept
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
        constexpr ZpNumber<> Zp_number() const noexcept
        {
            return normalize();
        }

        template<typename Self>
        constexpr operator Zp_normalized_t(this Self&& self) noexcept
        {
            return std::forward<Self>(self).normalize();
        }

        constexpr ZpNumber2<Head> normalize_rests() const noexcept
        {
            auto result = data.create<ZpNumber2<Head>>();
            data(result)[0] = 0;
            for(size_t i = 0; i < n_chunks2 - 1; ++i)
            {
                data(result)[i] += data_[i] & base_mask;
                data(result)[i + 1] = data_[i] >> base_bits;
            }
            return result;
        }

        constexpr ZpNumber<> normalize() const
        {
            auto result = data.create<ZpNumber<>>();
            miracl_core::mod(data(result), auto{ data_ }, p_data);
            return result;
        }

        // void show() const
        // {
        //     BLS12381_BIG::BIG_output(data(normalize()));
        // }

        constexpr auto operator-() const
        {
            auto result = data.create<ZpNumber<>>();
            miracl_core::mod(data(result), data(Zp_number()), p_data);
            miracl_core::mod_negate(data(result), data(result), p_data);
            return result;

            // Error in some case
            // constexpr auto head = ChunkRange{ Head.max - 1, Head.max } - Head;
            // constexpr auto rest = default_range - Rest;
            // if constexpr(not head_range_extrem2.contains(head))
            // {
            //     return -normalize();
            // }
            // else if constexpr(not rest_range_extrem.contains(rest))
            // {
            //     return -normalize_rests();
            // }
            // else
            // {
            //     constexpr auto np2n = get_np2n<Head.max>();

            //     auto result = data.create<ZpNumber2<head, rest>>();
            //     for(size_t i = 0; i < n_chunks2; ++i)
            //     {
            //         data(result)[i] = data(np2n)[i] - data_[i];
            //     }
            //     return result;
            // }
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
        friend constexpr auto operator/(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            return l * inverse(r);
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr auto operator/(const ZpNumber2& l, const ZpNumber<RHead, RRest>& r) noexcept
        {
            return l * inverse(r);
        }

        template<ChunkRange LHead, ChunkRange LRest>
        friend constexpr auto operator/(const ZpNumber<LHead, LRest>& l, const ZpNumber2& r) noexcept
        {
            return l * inverse(r);
        }

        template<ChunkRange RHead, ChunkRange RRest>
        friend constexpr bool operator==(const ZpNumber2& l, const ZpNumber2<RHead, RRest>& r) noexcept
        {
            return data(l.normalize()) == data(r.normalize());
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, ZpNumber2>
        friend constexpr auto sum(std::type_identity<ZpNumber2>, R&& r) 
        {
            if constexpr(Rest.min == 0 && Rest.max == 0)
            {
                return ZpNumber2{};
            }
            else if(std::ranges::size(r) == 0)
            {
                return data.create<ZpNumber2<>>();
            }
            else
            {
                constexpr size_t n = head_range_extrem / Head - 1;
                constexpr size_t m = rest_range_extrem / Rest - 1;
                if constexpr(n == 0)
                {
                    return sum(constant<Zp>, std::forward<R>(r) 
                    | std::views::transform([]<typename E>(E&& e){ 
                        return std::forward<E>(e).normalize(); 
                    }));
                }
                else if constexpr(m == 0)
                {
                    return sum(constant<Zp>, std::forward<R>(r)
                    | std::views::transform([]<typename E>(E&& e){
                        return std::forward<E>(e).normalize_rests(); 
                    }));
                }
                else
                {
                    auto result = data.create<ZpNumber2<>>();
                    auto i = std::ranges::begin(r);
                    data(result) = data(*i);
                    size_t j = 0;
                    size_t k = 0;
                    for(++i; i != std::ranges::end(r); ++i)
                    {
                        data(result) = data(result + *i);
                        ++j;
                        ++k;
                        if(j == n)
                        {
                            data(result) = data(result.normalize());
                            j = 0;
                            k = 0;
                            continue;
                        }
                        if(k == n)
                        {
                            data(result) = data(result.normalize_rests());
                            k = 0;
                            continue;
                        }
                    }
                    if(j != 0)
                    {
                        data(result) = data(result.normalize());
                    }
                    else if(k != 0)
                    {
                        data(result) = data(result.normalize_rests());
                    }
                    return result;
                }
            }
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, ZpNumber2>
        friend constexpr auto product(std::type_identity<ZpNumber2>, R&& r) 
        {
            auto iter = std::ranges::begin(r);
            auto result = (*iter).Zp_number();
            auto& x = data(result);
            for(auto i = ++iter; i != std::ranges::end(r); ++i)
            {
                x = data((result * *i).Zp_number());
            }
            return result;
        }

    private:
        constexpr ZpNumber2() noexcept = default;

        template<size_t N>
        static consteval auto get_np2n()
        {
            return (data.create<ZpNumber2<>>(p2n_data) * constant_t<N>{}).normalize_rests();
        }

        ZpNumber2Data data_;
    };
    
    template<Zp_element T>
    constexpr void serialize_to(std::span<char, serialized_size<Zp>> bytes, T&& t)
    {
        std::forward<T>(t).Zp_number().serialize(bytes);
    }
}

namespace crypto12381::detail::sets 
{
    constexpr auto select_in(constant_t<Zp>, RandomEngine& random) noexcept
    {
        return detail::ZpNumber<>::select(random);
    }

    constexpr auto select_in(constant_t<*Zp>, RandomEngine& random) noexcept
    {
        return detail::ZpNumber<>::select_except0(random);
    }

    constexpr auto parse(constant_t<Zp>, std::span<const char, serialized_size<Zp>> bytes)
    {
        return detail::ZpNumber<>{ bytes };
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

        return std::move(result) | algebraic;
    }

    inline auto hash_to(hash_state&& state, Zp_t) noexcept
    {
        return Zp_normalized_t::from_hash(std::move(state));
    }
}

namespace crypto12381 
{
    namespace detail 
    {
        struct make_Zp_fn : symbolic_functor_interface<make_Zp_fn>
        {
            using symbolic_functor_interface<make_Zp_fn>::operator();

            template<std::integral T> requires (sizeof(T) <= serialized_size<Zp>)
            static auto operator()(T x) noexcept
            {
                if constexpr(std::signed_integral<T>)
                {
                    if(x >= 0)
                    {
                        return make_Zp((std::make_unsigned_t<T>)x);
                    }
                    else
                    {
                        return (detail::ZpNumber<>)-make_Zp((std::make_unsigned_t<T>)-x);
                    }
                }
                else
                {
                    x = std::byteswap(x);
                    serialized_field<Zp> buffer{};
                    std::memcpy(buffer.data() + (serialized_size<Zp> - sizeof(T)), &x, sizeof(T));
                    return detail::ZpNumber<>{ buffer };
                }
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::make_Zp_fn make_Zp{};
    }

    namespace detail 
    {
        struct polynomial_fn : symbolic_functor_interface<polynomial_fn>
        {
            using symbolic_functor_interface<polynomial_fn>::operator();

            template<not_symbolic Tx, not_symbolic Ta0, not_symbolic Ra>
            static constexpr decltype(auto) operator()(Tx&& x, Ta0&& a0, Ra&& a)
            {
                if constexpr(std::integral<std::remove_cvref_t<Tx>>)
                {
                    using type = std::remove_cvref_t<Tx>;
                    auto n = std::ranges::size(a);
                    auto a_ = (Ra&&)a | algebraic; 
                    auto x_pow = sequence(1, n) 
                    | transform([&](auto i){ return make_Zp((type)std::pow(x, i)); });
                    return a0 + Σ[n - 1](a_[i] * x_pow[i]);
                }
                else
                {
                    static_assert("false", "Not implement yet.");
                }
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::polynomial_fn polynomial{};
    }
}

#endif