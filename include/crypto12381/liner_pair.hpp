#ifndef CRYPTO12381_LINER_PAIR_HPP
#define CRYPTO12381_LINER_PAIR_HPP

#include "miracl_core_interface.hpp"

#include "g1_point.hpp"
#include "g2_point.hpp"

namespace crypto12381
{
    namespace detail 
    {
        class GTPoint;

        template<typename P, typename V>
        class GTPair;
    }

    template<typename T>
    concept GT_element = element_of<T, GT>;
}

namespace crypto12381::detail::sets
{
    template<typename T>
    consteval bool contains(constant_t<GT_t{}>, std::type_identity<T>) noexcept
    {
        return std::convertible_to<T, GTPoint> && requires(T&& t)
        {
            { t.GT_point() } -> detail::specified<detail::GTPoint>;
        };
    }
}

namespace crypto12381::detail
{
    template<typename T>
    concept gt_reusable = std::is_object_v<decltype(std::declval<T>().GT_point())> || 
            std::is_rvalue_reference_v<decltype(std::declval<T>().GT_point())>;

    struct GTPointData
    {
        miracl_core::fp12 fp;

        constexpr operator miracl_core::fp12&() noexcept
        {
            return fp;
        }

        constexpr operator const miracl_core::fp12&()const noexcept
        {
            return fp;
        }
    };

    class GTPoint
    {
        friend DataAccessor;
    public:
        constexpr GTPoint(const GTPoint&) = default;
        constexpr GTPoint(GTPoint&&) = default;

        void serialize(std::span<char, serialized_size<GT>> bytes) const noexcept
        {
            miracl_core::bytes_view buffer_view{
                .len = 0,
                .max = serialized_size<GT>,
                .data = bytes.data()
            };
            miracl_core::to_bytes(buffer_view, auto{ data_ });
        }

        template<typename Self>
        constexpr decltype(auto) GT_point(this Self&& self) noexcept
        {
            if constexpr(std::is_const_v<std::remove_reference_t<Self>>)
            {
                return GTPoint{ std::forward<Self>(self) };
            }
            else
            {
                return std::forward<Self>(self);
            }
        }

        // void show() const
        // {
        //     BLS12381::FP12_output(data(GT_point()));
        // }

        template<GT_element Self>
        friend constexpr GTPoint inverse(Self&& self) noexcept
        {
            if constexpr(gt_reusable<Self>)
            {
                decltype(auto) result = std::forward<Self>(self).GT_point();
                miracl_core::inverse(result.data_, result.data_);
                return result;
            }
            else
            {
                GTPoint result = std::forward<Self>(self).GT_point();
                miracl_core::inverse(result.data_, result.data_);
                return result;
            }
        }

        template<GT_element L, GT_element R> requires specified<L, GTPoint> || specified<R, GTPoint>
        friend constexpr GTPoint operator*(L&& l, R&& r) noexcept
        {
            if constexpr(gt_reusable<L>)
            {
                decltype(auto) result = l.GT_point();
                miracl_core::multiply(result.data_, r.GT_point().data_);
                return result;
            }
            else if constexpr(gt_reusable<R>)
            {
                decltype(auto) result = r.GT_point();
                miracl_core::multiply(result.data_, l.GT_point().data_);
                return result;
            }
            else
            {
                GTPoint result = l.GT_point();
                miracl_core::multiply(result.data_, r.GT_point().data_);
                return result;
            }
        }

        template<GT_element L, GT_element R>
        friend constexpr GTPoint operator/(L&& l, R&& r) noexcept
        {
            return l * inverse(r);
        }

        template<specified<GTPoint> P, Zp_element V>
        friend constexpr auto operator^(P&& point, V&& number) noexcept
        {
            if constexpr(gt_reusable<P>)
            {
                decltype(auto) result = std::forward<P>(point).GT_point();
                miracl_core::pow(result.data_, result.data_, data(std::forward<V>(number).Zp_number()));
                return result;
            }
            else
            {
                GTPoint result = std::forward<P>(point).GT_point();
                miracl_core::pow(result.data_, result.data_, data(std::forward<V>(number).Zp_number()));
                return result;
            }
        }

        template<specified<GTPoint> L, GT_element R>
        friend constexpr bool operator==(L&& l, R&& r) noexcept
        {
            return miracl_core::equal(data(l.GT_point()), data(r.GT_point())) == 1;
        }

    private:
        constexpr GTPoint() noexcept = default;

        GTPoint& operator=(const GTPoint&) = default;
        GTPoint& operator=(GTPoint&&) = default;

        GTPointData data_;
    };

    template<typename P1, typename P2>
    class GTPair
    {
        friend DataAccessor;
        template<typename, typename>
        friend class GTPair;
    public:
        template<G1_element P1_, G2_element P2_>
        friend constexpr GTPair<P1_, P2_> pair(P1_&& p1, P2_&& p2) noexcept;

        template<typename Self>
        operator GTPoint(this Self&& self) noexcept
        {
            return std::forward<Self>(self).GT_point();
        }

        template<typename Self>
        constexpr GTPoint GT_point(this Self&& self) noexcept
        {
            auto result = data.create<GTPoint>();
            miracl_core::pair_ate(
                data(result),
                data(std::forward<Self>(self).p2().G2_point()), 
                data(std::forward<Self>(self).p1().G1_point())
            );
            miracl_core::pair_final_exponentiation(data(result));
            return result;
        }

        // void show() const
        // {
        //     BLS12381::FP12_output(data(GT_point()));
        // }

        template<specified<GTPair> L, GT_element R> requires (not specified<R, GTPoint>)
        friend constexpr GTPoint operator*(L&& l, R&& r) noexcept
        {
            auto result = data.create<GTPoint>();
            miracl_core::pair_double_ate(
                data(result),
                data(std::forward<L>(l).p2().G2_point()), 
                data(std::forward<L>(l).p1().G1_point()), 
                data(std::forward<R>(r).p2().G2_point()), 
                data(std::forward<R>(r).p1().G1_point())
            );
            miracl_core::pair_final_exponentiation(data(result));
            return result;
        }

        template<specified<GTPair> P, Zp_element V>
        friend constexpr auto operator^(P&& point, V&& number) noexcept
        {
            return (GTPoint)std::forward<P>(point) ^ number;
        }

        template<specified<GTPair> L, GT_element R>
        friend constexpr bool operator==(L&& l, R&& r) noexcept
        {
            return miracl_core::equal(data(l.GT_point()), data(r.GT_point())) == 1;
        }
    private:
        constexpr explicit GTPair(P1&& p1, P2&& p2) noexcept
        : data_{ std::forward<P1>(p1), std::forward<P2>(p2) }
        {}

        template<typename Self>
        constexpr decltype(auto) p1(this Self&& self) noexcept
        {
            return std::get<0>(std::forward_like<Self>(self.data_));
        }

        template<typename Self>
        constexpr decltype(auto) p2(this Self&& self) noexcept
        {
            return std::get<1>(std::forward_like<Self>(self.data_));
        }

        std::tuple<P1, P2> data_;
    };

    template<G1_element P1, G2_element P2>
    constexpr GTPair<P1, P2> pair(P1&& p1, P2&& p2) noexcept
    {
        return GTPair<P1, P2>{ std::forward<P1>(p1), std::forward<P2>(p2) };
    }

    template<GT_element T>
    constexpr void serialize_to(std::span<char, serialized_size<GT>> bytes, T&& t)
    {
        std::forward<T>(t).GT_point().serialize(bytes);
    }
}

#endif