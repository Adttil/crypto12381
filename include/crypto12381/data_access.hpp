#ifndef CRYPTO12381_DATA_ACCESS_HPP
#define CRYPTO12381_DATA_ACCESS_HPP

#include <utility>

#include "chunk_range.hpp"

namespace crypto12381::detail
{
    class DataAccessor
    {
        //constexpr DataAccessor()noexcept = default;

        template<class T>
        static constexpr decltype(auto) operator()(T&& t) noexcept
        {
            return std::forward_like<T>(t.data_);
        }

        template<class T>
        friend constexpr decltype(auto) operator|(T&& t, DataAccessor) noexcept
        {
            return DataAccessor::operator()(std::forward<T>(t));
        }

        template<class T>
        static constexpr T create() noexcept
        {
            if consteval
            {
                return T{};
            }
            else
            {
                T t;
                return t;
            }
        }

        template<class T, class Data>
        static constexpr T create(Data&& data) noexcept
        {
            T t = create<T>();
            t.data_ = data;
            return t;
        }

        friend struct Zp_t;

        template<ChunkRange, ChunkRange>
        friend class ZpNumber;

        template<ChunkRange, ChunkRange>
        friend class ZpNumber2;

        friend class G1Point;

        template<typename, typename>
        friend class G1Pow;

        friend class G2Point;

        friend class GTPoint;

        template<typename, typename >
        friend class GTPair;
    };

    inline constexpr DataAccessor data;
}

#endif