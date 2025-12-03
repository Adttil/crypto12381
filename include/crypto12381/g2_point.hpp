#ifndef CRYPTO12381_G2_POINT_HPP
#define CRYPTO12381_G2_POINT_HPP

#include <cstring>
#include <tuple>
#include <miracl-core/bls_BLS12381.h>

#include "general.hpp"
#include "zp_number.hpp"

namespace crypto12381
{
    namespace detail 
    {
        class G2Point;

        template<typename P, typename V>
        class G1Pow;
    }

    template<typename T>
    concept G2_element = element_of<T, G2>;
}

namespace crypto12381::detail::sets
{
    struct G2_except_identity_t{};
    
    constexpr G2_except_identity_t operator*(G2_t) noexcept
    {
        return {};
    }

    template<typename T>
    consteval bool contains(constant_t<G2>, std::type_identity<T>) noexcept
    {
        return std::convertible_to<T, G2Point> && requires(T&& t)
        {
            { t.G2_point() } -> detail::specified<detail::G2Point>;
        };
    }
}

namespace crypto12381::detail
{
    template<typename T>
    concept g2_reusable = std::is_object_v<decltype(std::declval<T>().G2_point())> || 
            std::is_rvalue_reference_v<decltype(std::declval<T>().G2_point())>;

    struct G2PointData
    {
        BLS12381::ECP2 ecp;

        constexpr operator BLS12381::ECP2*()
        {
            return &ecp;
        }
    };

    class G2Point
    {
        friend DataAccessor;
    public:
        constexpr explicit G2Point(serialized_view<G2> bytes)
        {
            serialized_field<G2> buffer;
            std::memcpy(buffer.data(), bytes.data(), serialized_size<G2>);
            core::octet buffer_view{
                .len = serialized_size<G2>,
                .max = serialized_size<G2>,
                .val = buffer.data()
            };
            BLS12381::ECP2_fromOctet(data_, &buffer_view);
        }

        constexpr G2Point(const G2Point&) = default;
        constexpr G2Point(G2Point&&) = default;

        void serialize(std::span<char, serialized_size<G2>> bytes) const noexcept
        {
            core::octet buffer_view{
                .len = 0,
                .max = serialized_size<G2>,
                .val = bytes.data()
            };
            BLS12381::ECP2_toOctet(&buffer_view, auto{ data_ }, true);
        }

        template<typename Self>
        constexpr decltype(auto) G2_point(this Self&& self) noexcept
        {
            if constexpr(std::is_const_v<std::remove_reference_t<Self>>)
            {
                return G2Point{ std::forward<Self>(self) };
            }
            else
            {
                return std::forward<Self>(self);
            }
        }

        static const G2Point& default_generator() noexcept
        {
            return get_default_generator();
        }

        static constexpr G2Point select(RandomEngine& random)
        {
            auto result = G2Point::default_generator();
            auto x = crypto12381::select_in<Zp>(random);
            BLS12381::PAIR_G2mul(result.data_, data(x));
            return result;
        }

        static constexpr G2Point select_except1(RandomEngine& random)
        {
            auto result = G2Point::default_generator();
            auto x = crypto12381::select_in<*Zp>(random);
            BLS12381::PAIR_G2mul(result.data_, data(x));
            return result;
        }

        template<G2_element Self>
        friend constexpr G2Point inverse(Self&& self) noexcept
        {
            if constexpr(g2_reusable<Self>)
            {
                decltype(auto) result = std::forward<Self>(self).G2_point();
                BLS12381::ECP2_neg(data(result));
                return result;
            }
            else
            {
                G2Point result = std::forward<Self>(self).G2_point();
                BLS12381::ECP2_neg(data(result));
                return result;
            }
        }

        template<G2_element L, G2_element R>
        friend constexpr G2Point operator*(L&& l, R&& r) noexcept
        {
            if constexpr(g2_reusable<L>)
            {
                decltype(auto) result = l.G2_point();
                BLS12381::ECP2_add(result.data_, r.G2_point().data_);
                return result;
            }
            else if constexpr(g2_reusable<R>)
            {
                decltype(auto) result = r.G2_point();
                BLS12381::ECP2_add(result.data_, l.G2_point().data_);
                return result;
            }
            else
            {
                G2Point result = l.G2_point();
                BLS12381::ECP2_add(result.data_, r.G2_point().data_);
                return result;
            }
        }

        template<G2_element L, G2_element R>
        friend constexpr G2Point operator/(L&& l, R&& r) noexcept
        {
            if constexpr(g2_reusable<L>)
            {
                decltype(auto) result = l.G2_point();
                BLS12381::ECP2_sub(result.data_, r.G2_point().data_);
                return result;
            }
            else
            {
                G2Point result = l.G2_point();
                BLS12381::ECP2_sub(result.data_, r.G2_point().data_);
                return result;
            }
        }

        template<G2_element P, Zp_element V>
        friend constexpr auto operator^(P&& point, V&& number) noexcept
        {
            if constexpr(g2_reusable<P>)
            {
                decltype(auto) result = point.G2_point();
                BLS12381::PAIR_G2mul(result.data_, data(number.Zp_number()));
                return result;
            }
            else
            {
                auto result = point.G2_point();
                BLS12381::PAIR_G2mul(result.data_, data(number.Zp_number()));
                return result;
            }
        }

        template<G2_element L, G2_element R>
        friend constexpr bool operator==(L&& l, R&& r) noexcept
        {
            return BLS12381::ECP2_equals(data(l.G2_point()), data(r.G2_point())) == 1;
        }

        template<std::ranges::range R> 
        requires specified<std::ranges::range_value_t<R>, G2Point>
        friend constexpr auto product(std::type_identity<G2Point>, R&& r) 
        {
            G2Point result;
            BLS12381::ECP2_inf(result.data_);
            for(auto&& p : std::forward<R>(r))
            {
                BLS12381::ECP2_add(result.data_, p.G2_point().data_);
            }
            return result;
        }

    private:
        constexpr G2Point() noexcept = default;

        G2Point& operator=(const G2Point&) = default;
        G2Point& operator=(G2Point&&) = default;
        
        static G2Point& get_default_generator() noexcept
        {
            static G2Point point = []()
            {
                G2Point g2;
                BLS12381::ECP2_generator(g2.data_);
                return g2;
            }();

            return point;
        }

        G2PointData data_;
    };
    
    template<G2_element T>
    constexpr void serialize_to(std::span<char, serialized_size<G2>> bytes, T&& t)
    {
        std::forward<T>(t).G2_point().serialize(bytes);
    }
}

namespace crypto12381::detail::sets 
{
    constexpr auto select_in(constant_t<G2>, RandomEngine& random) noexcept
    {
        return G2Point::select(random);
    }

    constexpr auto select_in(constant_t<*G2>, RandomEngine& random) noexcept
    {
        return G2Point::select_except1(random);
    }

    constexpr auto parse(constant_t<G2>, serialized_view<G2> bytes)
    {
        return detail::G2Point{ bytes };
    }
}

#endif