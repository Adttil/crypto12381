#ifndef CRYPTO12381_G1_POINT_HPP
#define CRYPTO12381_G1_POINT_HPP

#include <tuple>
#include <miracl-core/bls_BLS12381.h>

#include "general.hpp"
#include "zp_number.hpp"

namespace crypto12381
{
    namespace detail 
    {
        class G1Point;

        template<typename P, typename V>
        class G1Pow;
    }

    template<typename T>
    concept G1_element = element_of<T, G1>;
}

namespace crypto12381::detail::sets 
{
    struct G1_except_identity_t{};
    
    constexpr G1_except_identity_t operator*(G1_t) noexcept
    {
        return {};
    }

    template<typename T>
    consteval bool contains(constant_t<G1_t{}>, std::type_identity<T>) noexcept
    {
        return std::convertible_to<T, G1Point> && requires(T&& t)
        {
            { t.G1_point() } -> detail::specified<detail::G1Point>;
        };
    }
}

namespace crypto12381::detail
{
    template<typename T>
    concept g1_reusable = std::is_object_v<decltype(std::declval<T>().G1_point())> || 
            std::is_rvalue_reference_v<decltype(std::declval<T>().G1_point())>;

    struct G1PointData
    {
        BLS12381::ECP ecp;

        constexpr operator BLS12381::ECP*()
        {
            return &ecp;
        }
    };

    inline constexpr ZpNumberData modulus_data = {
        0x1FEFFFFFFFFAAABL,
        0x2FFFFAC54FFFFEEL,
        0x12A0F6B0F6241EAL,
        0x213CE144AFD9CC3L,
        0x2434BACD764774BL,
        0x25FF9A692C6E9EDL,
        0x1A0111EA3L
    };

    constexpr ZpNumberData& modulus() noexcept
    {
        thread_local constinit auto modulus = modulus_data;
        return modulus;
    }

    class G1Point
    {
        friend DataAccessor;
    public:
        constexpr explicit G1Point(serialized_view<G1> bytes)
        {
            serialized_field<G1> buffer;
            std::memcpy(buffer.data(), bytes.data(), serialized_size<G1>);
            core::octet buffer_view{
                .len = serialized_size<G1>,
                .max = serialized_size<G1>,
                .val = buffer.data()
            };
            BLS12381::ECP_fromOctet(data_, &buffer_view);
        }

        constexpr G1Point(const G1Point&) = default;
        constexpr G1Point(G1Point&&) = default;

        void serialize(std::span<char, serialized_size<G1>> bytes) const noexcept
        {
            core::octet buffer_view{
                .len = 0,
                .max = serialized_size<G1>,
                .val = bytes.data()
            };
            BLS12381::ECP_toOctet(&buffer_view, auto{ data_ }, true);
        }

        template<typename Self>
        constexpr decltype(auto) G1_point(this Self&& self) noexcept
        {
            if constexpr(std::is_const_v<std::remove_reference_t<Self>>)
            {
                return G1Point{ std::forward<Self>(self) };
            }
            else
            {
                return std::forward<Self>(self);
            }
        }

        void show() const
        {
            BLS12381::ECP_output(data(G1_point()));
        }

        static const G1Point& default_generator() noexcept
        {
            return get_default_generator();
        }

        template<G1_element Self>
        friend constexpr G1Point inverse(Self&& self) noexcept
        {
            if constexpr(g1_reusable<Self>)
            {
                decltype(auto) result = std::forward<Self>(self).G1_point();
                BLS12381::ECP_neg(data(result));
                return result;
            }
            else
            {
                G1Point result = std::forward<Self>(self).G1_point();
                BLS12381::ECP_neg(data(result));
                return result;
            }
        }

        template<G1_element L, G1_element R> requires specified<L, G1Point> || specified<R, G1Point>
        friend constexpr G1Point operator*(L&& l, R&& r) noexcept
        {
            if constexpr(g1_reusable<L>)
            {
                decltype(auto) result = l.G1_point();
                BLS12381::ECP_add(result.data_, r.G1_point().data_);
                return result;
            }
            else if constexpr(g1_reusable<R>)
            {
                decltype(auto) result = r.G1_point();
                BLS12381::ECP_add(result.data_, l.G1_point().data_);
                return result;
            }
            else
            {
                G1Point result = l.G1_point();
                BLS12381::ECP_add(result.data_, r.G1_point().data_);
                return result;
            }
        }

        template<G1_element L, G1_element R>
        friend constexpr G1Point operator/(L&& l, R&& r) noexcept
        {
            if constexpr(g1_reusable<L>)
            {
                decltype(auto) result = l.G1_point();
                BLS12381::ECP_sub(result.data_, r.G1_point().data_);
                return result;
            }
            else
            {
                G1Point result = l.G1_point();
                BLS12381::ECP_sub(result.data_, r.G1_point().data_);
                return result;
            }
        }

        template<G1_element P, Zp_element V>
        friend constexpr auto operator^(P&& point, V&& number) noexcept
        {
            return G1Pow<P, V>{ std::forward<P>(point), std::forward<V>(number) };
        }

        template<G1_element L, G1_element R>
        friend constexpr bool operator==(L&& l, R&& r) noexcept
        {
            return BLS12381::ECP_equals(data(l.G1_point()), data(r.G1_point())) == 1;
        }

        static G1Point from_hash(hash_state&& state) noexcept
        {
            char hash_bytes[hash_state::hash_size];
            std::move(state).to(hash_bytes);
            BLS12381_BIG::DBIG dbig;
            BLS12381_BIG::BIG_dfromBytesLen(dbig, hash_bytes, hash_state::hash_size);
            BLS12381_BIG::BIG x;
            BLS12381_BIG::BIG_ctdmod(x, dbig, modulus(), hash_state::hash_size * 8 - 381);
            BLS12381_FP::FP fp;
            BLS12381_FP::FP_nres(&fp, x);

            G1Point result;
            BLS12381::ECP_map2point(result.data_, &fp);
            BLS12381::ECP_cfp(result.data_);
            return result;
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, G1Point>
        friend constexpr auto product(std::type_identity<G1Point>, R&& r) 
        {
            G1Point result;
            BLS12381::ECP_inf(result.data_);
            for(auto&& p : std::forward<R>(r))
            {
                BLS12381::ECP_add(result.data_, p.G1_point().data_);
            }
            return result;
        }

    private:
        constexpr G1Point() noexcept = default;

        G1Point& operator=(const G1Point&) = default;
        G1Point& operator=(G1Point&&) = default;
        
        static G1Point& get_default_generator() noexcept
        {
            static G1Point point = []()
            {
                G1Point g1;
                BLS12381::ECP_generator(g1.data_);
                return g1;
            }();

            return point;
        }

        G1PointData data_;
    };

    template<typename P, typename V>
    class G1Pow
    {
        friend G1Point;
        friend DataAccessor;
        template<typename, typename>
        friend class G1Pow;
    public:
        G1Pow() = delete;
        
        // constexpr explicit G1Pow(P&& point, V&& number) noexcept
        // requires G1_element<P> && Zp_element<V>
        // : data_{ std::forward<P>(point), std::forward<V>(number) }
        // {}

        template<typename Self>
        operator G1Point(this Self&& self) noexcept
        {
            return std::forward<Self>(self).G1_point();
        }

        template<typename Self>
        constexpr G1Point G1_point(this Self&& self) noexcept
        {
            if constexpr(std::is_rvalue_reference_v<decltype(std::forward<Self>(self).point())>)
            {
                decltype(auto) result = std::forward<Self>(self).point().G1_point();
                BLS12381::PAIR_G1mul(data(result), data(std::forward<Self>(self).number().Zp_number()));
                return result;
            }
            else
            {
                G1Point result = std::forward<Self>(self).point().G1_point();
                BLS12381::PAIR_G1mul(data(result), data(std::forward<Self>(self).number().Zp_number()));
                return result;
            }
        }

        void show() const
        {
            BLS12381::ECP_output(data(G1_point()));
        }

        template<specified<G1Pow> L, G1_element R> requires (not specified<R, G1Point>)
        friend constexpr G1Point operator*(L&& l, R&& r) noexcept
        {
            if constexpr(g1_reusable<decltype(std::forward<L>(l).point())>)
            {
                decltype(auto) result = std::forward<L>(l).point().G1_point();
                BLS12381::ECP_mul2(
                    data(result), 
                    data(std::forward<R>(r).point().G1_point()), 
                    data(std::forward<L>(l).number().Zp_number()),
                    data(std::forward<R>(r).number().Zp_number())
                );
                return result;
            }
            else if constexpr(g1_reusable<decltype(std::forward<R>(r).point())>)
            {
                decltype(auto) result = std::forward<R>(r).point().G1_point();
                BLS12381::ECP_mul2(
                    data(result), 
                    data(std::forward<L>(l).point().G1_point()), 
                    data(std::forward<R>(r).number().Zp_number()),
                    data(std::forward<L>(l).number().Zp_number())
                );
                return result;
            }
            else
            {
                G1Point result = std::forward<L>(l).point().G1_point();
                BLS12381::ECP_mul2(
                    data(result), 
                    data(std::forward<R>(r).point().G1_point()), 
                    data(std::forward<L>(l).number().Zp_number()),
                    data(std::forward<R>(r).number().Zp_number())
                );
                return result;
            }
        }

        static auto select(RandomEngine& random) noexcept
        {
            return G1Pow<G1Point&, ZpNumber<>>{ 
                const_cast<detail::G1Point&>(detail::G1Point::default_generator()), 
                crypto12381::select_in<Zp>(random) 
            };
        }

        static auto select_except1(RandomEngine& random) noexcept
        {
            return G1Pow<G1Point&, ZpNumber<>>{ 
                const_cast<detail::G1Point&>(detail::G1Point::default_generator()), 
                crypto12381::select_in<*Zp>(random) 
            };
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, G1Pow>
        friend constexpr auto product(std::type_identity<G1Pow>, R&& r) 
        {
            auto result = data.create<G1Point>();
            BLS12381::ECP_inf(data(result));
            for(auto&& p : std::forward<R>(r))
            {
                BLS12381::ECP_add(data(result), data(p.G1_point()));
            }
            return result;
        }
    private:
        constexpr explicit G1Pow(P&& point, V&& number) noexcept
        : data_{ std::forward<P>(point), std::forward<V>(number) }
        {}

        template<typename Self>
        constexpr decltype(auto) point(this Self&& self) noexcept
        {
            return std::get<0>(std::forward_like<Self>(self.data_));
        }

        template<typename Self>
        constexpr decltype(auto) number(this Self&& self) noexcept
        {
            return std::get<1>(std::forward_like<Self>(self.data_));
        }

        std::tuple<P, V> data_;
    };

    template<G1_element T>
    constexpr void serialize_to(std::span<char, serialized_size<G1>> bytes, T&& t)
    {
        std::forward<T>(t).G1_point().serialize(bytes);
    }
}

namespace crypto12381::detail::sets 
{
    constexpr auto select_in(constant_t<G1>, RandomEngine& random) noexcept
    {
        return G1Pow<G1Point&, ZpNumber<>>::select(random);
    }

    constexpr auto select_in(constant_t<*G1>, RandomEngine& random) noexcept
    {
        return G1Pow<G1Point&, ZpNumber<>>::select_except1(random);
    }

    constexpr auto parse(constant_t<G1>, serialized_view<G1> bytes)
    {
        return detail::G1Point{ bytes };
    }

    inline auto hash_to(hash_state&& state, G1_t) noexcept
    {
        return G1Point::from_hash(std::move(state));
    }
}

#endif