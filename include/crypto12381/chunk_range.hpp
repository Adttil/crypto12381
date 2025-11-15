#ifndef CRYPTO12381_CHUNK_RANGE_HPP
#define CRYPTO12381_CHUNK_RANGE_HPP

#include <algorithm>
#include <cstdint>

#include "constant.hpp"

namespace crypto12381::detail 
{
    using chunk_t = std::int64_t;

    struct ChunkRange
    {
        chunk_t min;
        chunk_t max;

        constexpr bool contains(const ChunkRange& subrange) const noexcept
        {
            return min <= subrange.min && max >= subrange.max;
        }
    };

    constexpr ChunkRange operator-(const ChunkRange& rng)noexcept
    {
        return { -rng.max, -rng.min };
    }

    constexpr ChunkRange operator+(const ChunkRange& l, const ChunkRange& r)noexcept
    {
        return { l.min + r.min, l.max + r.max };
    }

    constexpr ChunkRange operator*(const ChunkRange& l, const ChunkRange& r)noexcept
    {
        auto&& [min, max] = std::minmax({l.min * r.min, l.min * r.max, l.max * r.min, l.max * r.max});
        return { min, max };
    }

    constexpr ChunkRange operator-(const ChunkRange& l, const ChunkRange& r)noexcept
    {
        return { l.min - r.max, l.max - r.min };
    }

    template<std::integral auto Value>
    constexpr ChunkRange operator*(const ChunkRange& l, constant_t<Value>) noexcept
    {
        if constexpr(Value >= 0)
        {
            return { (chunk_t)Value * l.min, (chunk_t)Value * l.max };
        }
        else
        {
            return { (chunk_t)Value * l.max, (chunk_t)Value * l.min };
        }
    }

    template<std::integral T>
    constexpr int sign(T x)
    {
        if(x > 0)
        {
            return 1;
        }
        else if(x < 0)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }

    constexpr size_t operator/(const ChunkRange& l, const ChunkRange& r)noexcept
    {
        if(sign(l.min) != sign(r.min))
        {
            return l.max / r.max;
        }
        if(sign(l.max) != sign(r.max))
        {
            return l.min / r.min;
        }
        return std::min(l.max / r.max, l.min / r.min);
    }
}

#endif