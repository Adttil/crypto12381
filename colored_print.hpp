#ifndef ADTTIL_COLORED_PRINT_HPP
#define ADTTIL_COLORED_PRINT_HPP

#include <string_view>
#include <span>
#include <print>

namespace colored
{
    template<size_t N>
    struct fixed_string
    {
        char storage[N];

        constexpr fixed_string() = default;
        
        constexpr fixed_string(const char(&str)[N])
        {
            for(size_t i = 0; i < N; ++i)
            {
                storage[i] = str[i];
            }
        }

        static constexpr size_t size()
        {
            return N;
        }
    };

    template<size_t N>
    fixed_string(const char(&)[N]) -> fixed_string<N>;
    

    struct ColorInfo
    {
        const char* name;
        std::string_view flag;
    };

    inline constexpr ColorInfo color_table[]{
        { "reset", "\033[0m" },
        { "black", "\033[30m]" },
        { "red", "\033[31m" },
        { "green", "\033[32m" },
        { "yellow", "\033[33m" },
        { "blue", "\033[34m" },
        { "magenta", "\033[35m" },
        { "cyan", "\033[36m" },
        { "white", "\033[37m" },
        { "bold", "\033[1m" },
    };

    constexpr auto get_color_flag(std::string_view color_name)
    {
        for(auto& [name, flag] : color_table)
        {
            if(color_name == name)
            {
                return flag;
            }
        }
        return std::string_view{""};
    }

    constexpr bool read_word(const char*& in, std::string_view& word)
    {
        while(*in == ' '){ ++in; }
        if(not (*in >= 'a' && *in <= 'z'))
        {
            return false;
        }

        const char* start = in;
        while(*in >= 'a' && *in <= 'z')
        {
            ++in;
        }
        word = std::string_view{ start, in };
        return true;
    }

    constexpr size_t from_colored_format_string_on(std::string_view colored_fmt, std::span<char> fmt)
    {
        char* out = fmt.data();
        char* const end = fmt.data() + fmt.size();

        for(size_t i = 0; i < colored_fmt.size(); ++i)
        {
            char c = colored_fmt[i];
            if(c != '{' || colored_fmt[i + 1] == '{')
            {
                *out++ = c;
                continue;
            }
            c = colored_fmt[++i];
            while(c == ' ')
            {
                c = colored_fmt[++i];
            };
            if(not (c >= 'a' && c <= 'z') && c != '#')
            {
                *out++ = '{';
                *out++ = c;
                continue;
            }

            if(c == '#')
            {
                ++i;
                std::string_view word;
                const char* in = &colored_fmt[i];
                while (read_word(in, word))
                {
                    auto color_flag = get_color_flag(word);
                    for(auto c : color_flag)
                    {
                        *out++ = c;
                    }
                    // memcpy(out, color_flag.data(), color_flag.size());
                    // out += color_flag.size();
                }
                i += in - &colored_fmt[i];
                c = colored_fmt[i];

                while(c != '}')
                {
                    c = colored_fmt[++i];
                };
                continue;
            }

            std::string_view word;
            const char* in = &colored_fmt[i];
            while (read_word(in, word))
            {
                auto color_flag = get_color_flag(word);
                for(auto c : color_flag)
                {
                    *out++ = c;
                }
                // memcpy(out, color_flag.data(), color_flag.size());
                // out += color_flag.size();
            }
            i += in - &colored_fmt[i];
            c = colored_fmt[i];

            *out++ = '{';
            while(c != '}')
            {
                *out++ = c;
                c = colored_fmt[++i];
            };
            *out++ = '}';
            auto color_flag = get_color_flag("reset");
            for(auto c : color_flag)
            {
                *out++ = c;
            }
        }

        return out - fmt.data();
    }
    
    template<fixed_string Str>
    constexpr auto from_colored_format_string()
    {
        constexpr auto len_and_buffer = []()
        {
            struct Result
            {
                size_t length;
                char buffer[Str.size() * 2]{};
            } result{};

            result.length = from_colored_format_string_on(
                std::string_view{ Str.storage, Str.size() }, 
                std::span{ result.buffer } 
            );

            return result;
        }();

        constexpr size_t length = len_and_buffer.length;
        fixed_string<length> result;
        for(size_t i = 0; i < length; ++i)
        {
            result.storage[i] = len_and_buffer.buffer[i];
        }
        return result;
    }

    template<fixed_string Fmt, typename...Args>
    inline decltype(auto) print(Args&&...args)
    {
        static constexpr auto fmt = from_colored_format_string<Fmt>();
        return std::print(fmt.storage, std::forward<Args>(args)...);
    }

    template<fixed_string Fmt, typename...Args>
    inline decltype(auto) println(Args&&...args)
    {
        static constexpr auto fmt = from_colored_format_string<Fmt>();
        return std::println(fmt.storage, std::forward<Args>(args)...);
    }
}

#endif