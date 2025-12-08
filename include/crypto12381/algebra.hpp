#ifndef CRYPTO12381_ALGEBRA_HPP
#define CRYPTO12381_ALGEBRA_HPP

#include <array>
#include <ranges>
#include <functional>

namespace crypto12381 
{
    template<class T>
    struct symbolic_expression_interface;
    
    template<class T>
    concept symbolic = requires(std::remove_cvref_t<T>& t)
    {
        { []<class U>(symbolic_expression_interface<U>& t) -> U* {}(t) } -> std::same_as<std::remove_cvref_t<T>*>;
    } 
    || 
    (
        std::ranges::range<T>
        &&
        requires(std::remove_cvref_t<std::ranges::range_value_t<T>>& t)
        {
            { []<class U>(symbolic_expression_interface<U>& t) -> U* {}(t) }
                -> std::same_as<std::remove_cvref_t<std::ranges::range_value_t<T>>*>;
        } 
    );

    template<class T>
    concept not_symbolic = (not symbolic<T>);

    template<class F, class...Args>
    class symbolic_invocation;

    namespace detail
    {
        struct symbolic_invoke_fn
        {
            template<class F, class...Args>
            static constexpr decltype(auto) operator()(F&& fn, Args&&...args)
            {
                if constexpr((false || ... || symbolic<Args>))
                {
                    return symbolic_invocation<F, Args...>{ std::forward<F>(fn), std::forward<Args>(args)... };
                }
                else
                {
                    return std::forward<F>(fn)(std::forward<Args>(args)...);
                }
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::symbolic_invoke_fn symbolic_invoke{};
    }

    template<class T>
    struct symbolic_functor_interface
    {
        template<class...Args, class Self> requires (false || ... || symbolic<Args>)
        constexpr decltype(auto) operator()(this Self&& self, Args&&...args)
        {
            return symbolic_invocation<Self, Args...>{ std::forward<Self>(self), std::forward<Args>(args)... };
        }
    };

    template<std::ranges::range R>
    struct algebraic_range;

    template<class T>
    struct symbolic_functor_interface;

    namespace detail 
    {
        struct algebraic_fn : std::ranges::range_adaptor_closure<algebraic_fn>
        {
            template<std::ranges::range R>
            constexpr auto operator()(R&& r)const
            {
                if constexpr(std::ranges::random_access_range<R>)
                {
                    return algebraic_range<R>{ std::forward<R>(r) };
                }
                else
                {
                    return algebraic_range<decltype(std::forward<R>(r) | std::ranges::to<std::vector>())>{ 
                        std::forward<R>(r) | std::ranges::to<std::vector>() 
                    };
                }
            }

            template<class V>
            constexpr decltype(auto) operator()(algebraic_range<V>& v)const
            {
                return v;
            }

            template<class V>
            constexpr decltype(auto) operator()(const algebraic_range<V>& v)const
            {
                return v;
            }

            template<class V>
            constexpr decltype(auto) operator()(algebraic_range<V>&& v)const
            {
                return std::move(v);
            }

            template<class V>
            constexpr decltype(auto) operator()(const algebraic_range<V>&& v)const
            {
                return std::move(v);
            }
        };

        struct unwrap_fn : std::ranges::range_adaptor_closure<unwrap_fn>
        {
            template<std::ranges::range R>
            constexpr R&& operator()(R&& r)const
            {
                return std::forward<R>(r);
            }

            template<class V>
            constexpr decltype(auto) operator()(algebraic_range<V>& v)const
            {
                return v.base();
            }

            template<class V>
            constexpr decltype(auto) operator()(const algebraic_range<V>& v)const
            {
                return v.base();
            }

            template<class V>
            constexpr decltype(auto) operator()(algebraic_range<V>&& v)const
            {
                return std::move(v).base();
            }

            template<class V>
            constexpr decltype(auto) operator()(const algebraic_range<V>&& v)const
            {
                return std::move(v).base();
            }
        };
    }
    
    inline namespace functors 
    {
        inline constexpr detail::algebraic_fn algebraic{};

        inline constexpr detail::unwrap_fn unwrap{};

        inline constexpr auto materialize = unwrap | std::ranges::to<std::vector>() | algebraic;
    }

    namespace detail 
    {
        struct transform_fn
        {
            template<class Fn>
            constexpr auto operator()(Fn&& fn)const
            {
                return unwrap | std::views::transform(std::forward<Fn>(fn)) | algebraic;
            }
        };

        struct filter_fn
        {
            template<class Fn>
            constexpr auto operator()(Fn&& fn)const
            {
                return unwrap | std::views::filter(std::forward<Fn>(fn)) | algebraic;
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::transform_fn transform{};
        inline constexpr detail::filter_fn filter{};
    }

    namespace detail 
    {
        struct except_fn : symbolic_functor_interface<except_fn>
        {
            using symbolic_functor_interface<except_fn>::operator();

        template<class...Args>
        static constexpr decltype(auto) operator()(Args&&...args)
        {
            return filter([args = std::tuple<Args...>((Args&&)args...)](auto&& e){
                return [&]<size_t...I>(std::index_sequence<I...>){
                    return (true && ... && (e != std::get<I>(args)));
                }(std::index_sequence_for<Args...>{});
            });
        };
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::except_fn except;
    }
}

namespace crypto12381 
{
    template<size_t N>
    struct fixed_string
    {
        std::array<char, N> data;

        constexpr fixed_string(const char(&data)[N])
        : data{ std::to_array(data) }
        {}

        constexpr fixed_string(const char(&&data)[N])
        : data{ std::to_array(data) }
        {}

        friend bool operator==(const fixed_string&, const fixed_string&) = default;
    };

    template<size_t N>
    fixed_string(const char(&&)[N]) -> fixed_string<N>;

    
    template<fixed_string Name, class TValue, bool Ranged = false>
    struct symbol_substitution
    {
    public:
        static constexpr auto name = Name;
        
        TValue value;

        constexpr operator symbol_substitution<Name, const TValue&, Ranged>()const noexcept
        {
            return { value };
        }

        template<class...Args> requires Ranged
        constexpr decltype(auto) except(Args&&...args) &&
        {
            return symbol_substitution<Name, decltype((TValue&&)value | functors::except((Args&&)args...)), true>
            {
                (TValue&&)value | functors::except((Args&&)args...)
            };
        };

        constexpr symbol_substitution<Name, const TValue&, Ranged> ref()const & noexcept
        {
            return { value };
        }

        constexpr symbol_substitution<Name, const TValue&&, Ranged> ref()const && noexcept
        {
            return { value };
        }
    };

    namespace detail 
    {
        struct pass_fn
        {
            template<class T>
            static constexpr decltype(auto) operator()(T&& t)
            {
                return (T)t;
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::pass_fn pass;
    }    
}



namespace crypto12381 
{
    namespace detail::substitute_ns
    { 
        void substitute();

        template<class T>
        struct substitutiable_expr;

        template<class T, fixed_string Name, class TValue, bool Ranged>
        constexpr decltype(auto) operator||(T&& t, symbol_substitution<Name, TValue, Ranged> substitution)
        {
            if constexpr(requires{ std::forward<T>(t).substitute(std::move(substitution)); })
            {
                return std::forward<T>(t).substitute(std::move(substitution));
            }
            else if constexpr(requires{ substitute(std::forward<T>(t), std::move(substitution)); })
            {
                return substitute(std::forward<T>(t), std::move(substitution));
            }
            else if constexpr(Ranged)
            {
                if constexpr(symbolic<TValue>)
                {
                    auto substitute_fn = []<class U, class R>(U&& u, R&& r)
                    {
                        return ((U&&)u).value() || symbol_substitution<Name, R, true>{ (R&&)r };
                    };
                    return symbolic_invocation<decltype(substitute_fn), substitutiable_expr<T>, TValue>{
                        std::move(substitute_fn),
                        substitutiable_expr<T>{ (T&&)t },
                        (TValue&&)substitution.value
                    };
                }
                else return (TValue&&)substitution.value 
                    | transform([expr = std::tuple<T>{ (T&&)t }]<class E, class Self>(this Self&& self, E&& e){
                        return std::get<0>(std::forward_like<Self>(expr)) || symbol_substitution<Name, E>{ (E&&)e };
                    });
            }
            else
            {
                return std::forward<T>(t);
            }
        }

        struct substitute_fn
        {
            template<class T, fixed_string...Name, class...TValue, bool...Ranged>
            static constexpr decltype(auto) operator()(T&& t, symbol_substitution<Name, TValue, Ranged>...substitution)
            {
                return (std::forward<T>(t) || ... || std::move(substitution));
            }
        };

        template<class T>
        struct substitutiable_expr
        {
            std::tuple<T> value_;

            template<class Self>
            constexpr decltype(auto) value(this Self&& self) noexcept
            {
                return std::get<0>(std::forward_like<Self>(self.value_));
            }

            template<fixed_string Name, class TValue, class Self>
            constexpr auto substitute(this Self&& self, symbol_substitution<Name, TValue> substitution)
            {
                return substitutiable_expr<decltype(pass(substitute_fn{}(((Self&&)self).value(), substitution)))>
                {
                    substitute_fn{}(((Self&&)self).value(), substitution) 
                };
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::substitute_ns::substitute_fn substitute{};
    }

    template<class T>
    struct symbolic_expression_interface
    {
        template<class Self, fixed_string...Name, class...TValue, bool Ranged>
        constexpr decltype(auto) operator()(this Self&& self, symbol_substitution<Name, TValue, Ranged>...substitution)
        {
            return substitute(std::forward<Self>(self), std::move(substitution)...);
        }
    };

    template<fixed_string Name>
    struct symbol_in_fn;

    template<fixed_string Name>
    struct symbol : symbolic_expression_interface<symbol<Name>>
    {
        template<class TValue>
        constexpr symbol_substitution<Name, TValue> operator=(TValue&& value) const
        {
            return { std::forward<TValue>(value) };
        }

        static constexpr symbol_in_fn<Name> in{};

        template<class TValue, bool Ranged>
        constexpr TValue substitute(symbol_substitution<Name, TValue, Ranged> substitution) const
        {
            return (TValue&&)substitution.value;
        }
    };

    inline namespace literals
    {
        template<fixed_string Name>
        constexpr symbol<Name> operator ""_sym()
        {
            return {};
        }
    }

    template<fixed_string...Name>
    constexpr auto make_symbol() noexcept
    {
        if constexpr(sizeof...(Name) == 1uz)
        {
            return symbol<Name...>{};
        }
        else
        {
            return std::tuple<symbol<Name>...>{};
        };
    }

    template<class F, class...Args>
    class symbolic_invocation : public symbolic_expression_interface<symbolic_invocation<F, Args...>>
    {
    public:
        constexpr symbolic_invocation(F&& fn, Args&&...args)
        : fn_{ (F&&)fn }
        , args_{ std::forward<Args>(args)... }
        {}

        template<fixed_string Name, class TValue, class Self>
        constexpr decltype(auto) substitute(this Self&& self, symbol_substitution<Name, TValue> substitution)
        {
            if constexpr(sizeof...(Args) == 1uz)
            {
                return symbolic_invoke(
                    std::get<0>(std::forward_like<Self>(self.fn_)),
                    functors::substitute(std::get<0>(std::forward_like<Self>(self.args_)), std::move(substitution))
                );
            }
            else return [&]<size_t...I>(std::index_sequence<I...>){ 
                return symbolic_invoke(
                    std::get<0>(std::forward_like<Self>(self.fn_)),
                    functors::substitute(std::get<I>(std::forward_like<Self>(self.args_)), substitution)...
                );
            }(std::make_index_sequence<sizeof...(Args)>{});
        }
    private:
        std::tuple<F> fn_;
        std::tuple<Args...> args_;
    };

    namespace detail 
    {
        struct sequence_fn : symbolic_functor_interface<sequence_fn>
        {
            using symbolic_functor_interface<sequence_fn>::operator();

            template<class T> requires (not symbolic<T>)
            static constexpr auto operator()(T count) noexcept
            {
                return std::views::iota((T)0, count) | algebraic;
            }

            template<class Begin, class End> requires (not symbolic<Begin> && not symbolic<End>)
            static constexpr auto operator()(Begin begin, End end) noexcept
            {
                using type = std::common_type_t<Begin, End>;
                return std::views::iota((type)begin, (type)end) | algebraic;
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::sequence_fn sequence{};
    }

    template<fixed_string Name>
    struct symbol_in_fn
    {
        template<std::ranges::range R> requires (not symbolic<R>)
        static constexpr decltype(auto) operator()(R&& r)
        {
            return symbol_substitution<Name, R, true>{ (R&&)r };
        }

        template<symbolic R>
        static constexpr decltype(auto) operator()(R&& r)
        {
            return symbol_substitution<Name, R, true>{ (R&&)r };
        }

        template<class T>
        constexpr decltype(auto) operator[](T&& count)const
        {
            return operator()(sequence((T&&)count));
        }

        template<class TStart, class Sentinel>
        constexpr decltype(auto) operator[](TStart&& start, Sentinel&& sentinel)const
        {
            return operator()(sequence((TStart&&)start, (Sentinel&&)sentinel));
        }
    };

    inline namespace symbols 
    {
        inline constexpr symbol<"i"> i{};
        inline constexpr symbol<"j"> j{};
        inline constexpr symbol<"k"> k{};

        inline constexpr symbol<"x"> x{};
        inline constexpr symbol<"y"> y{};
        inline constexpr symbol<"z"> z{};
    }

    namespace detail 
    {
        struct subscript_fn : symbolic_functor_interface<subscript_fn>
        {
            using symbolic_functor_interface<subscript_fn>::operator();

            // template<std::ranges::range R, symbolic TIndex>
            // static constexpr decltype(auto) operator()(R&& r, TIndex&& index)
            // {
            //     return symbolic_invocation<subscript_fn, R, TIndex>{ 
            //         subscript_fn{}, 
            //         (R&&)r,
            //         (TIndex&&)(index) 
            //     };
            // }

            template<std::ranges::range R>
            static constexpr decltype(auto) operator()(R&& r, std::ranges::range_difference_t<R> i)
            {
                return std::ranges::begin(std::forward<R>(r))[i];
            }
        };
    }

    inline namespace functors 
    {
        inline constexpr detail::subscript_fn subscript{};
    }

    namespace detail 
    {
        template<typename T>
        constexpr T&& base_unwrap(T&& t) noexcept
        {
            return (T&&)t;
        }

        template<typename T>
        constexpr auto&& base_unwrap(std::ranges::owning_view<T>& t) noexcept
        {
            return t.base();
        }

        template<typename T>
        constexpr auto&& base_unwrap(const std::ranges::owning_view<T>& t) noexcept
        {
            return t.base();
        }
    }

    template<std::ranges::range R>
    struct algebraic_range
    {
    private:
        R base_{};
    public:
        algebraic_range() requires std::default_initializable<R> = default;

        constexpr algebraic_range(R&& base) 
        noexcept(std::is_nothrow_move_constructible_v<R>)
        : base_{ (R&&)base }
        {}

        // algebraic_range(algebraic_range&&)            = default;
        // algebraic_range& operator=(algebraic_range&&) = default;

        template<class T> requires std::convertible_to<std::ranges::range_reference_t<R>, T>
        constexpr operator std::vector<T>(this algebraic_range&& self)
        {
            return (algebraic_range&&)self 
            | std::views::transform([]<class U>(U&& u) -> T { return (U&&)u; })
            | std::ranges::to<std::vector>();
        }

        template<class Self>
        constexpr auto&& base(this Self&& self) noexcept
        {
            if constexpr(std::is_lvalue_reference_v<R>)
            {
                return self.base_;
            }
            else
            {
                return std::forward_like<Self>(self.base_);
            }
        }

        template<class Self>
        constexpr auto begin(this Self&& self)
        {
            return std::ranges::begin(self.base_);
        }

        template<class Self>
        constexpr auto end(this Self&& self)
        {
            return std::ranges::end(self.base_);
        }

        template<class Self>
        constexpr auto size(this Self&& self) requires std::ranges::sized_range<R>
        {
            return std::ranges::size(self.base_);
        }

        template<class Self>
        constexpr auto data(this Self&& self)
            requires std::ranges::contiguous_range<std::remove_reference_t<decltype(self.base_)>>
        {
            return std::ranges::data(self.base_);
        }

        constexpr bool empty() const
        {
            return std::ranges::empty(base_);
        }

        template<typename Self> requires std::ranges::random_access_range<R>
        constexpr decltype(auto) operator[](this Self&& self, std::ranges::range_difference_t<R> i)
        {
            return std::ranges::begin(self.base_)[i];
        }

        template<symbolic Index, typename Self>
        constexpr decltype(auto) operator[](this Self&& self, Index&& index)
        {
            return subscript(std::forward<Self>(self).base(), std::forward<Index>(index));
        }
    };

    template<symbolic T>
    constexpr auto operator-(T&& t)
    {
        return symbolic_invoke(std::negate<>{}, (T&&)t);
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator+(L&& left, R&& right)
    {
        return symbolic_invoke(std::plus<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator-(L&& left, R&& right)
    {
        return symbolic_invoke(std::minus<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator*(L&& left, R&& right)
    {
        return symbolic_invoke(std::multiplies<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator/(L&& left, R&& right)
    {
        return symbolic_invoke(std::divides<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator|(L&& left, R&& right)
    {
        return symbolic_invoke(std::bit_or<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    template<class L, class R> requires (symbolic<L> || symbolic<R>)
    constexpr auto operator^(L&& left, R&& right)
    {
        return symbolic_invoke(std::bit_xor<>{}, std::forward<L>(left), std::forward<R>(right));
    }

    // namespace detail 
    // {
    //     struct zip_transform_fn : symbolic_functor_interface<zip_transform_fn>
    //     {
    //         using symbolic_functor_interface<zip_transform_fn>::operator();

    //         template<not_symbolic F, not_symbolic...R>
    //         static constexpr decltype(auto) operator()(F&& fn, R&&...ranges)
    //         {
    //             return std::views::zip_transform(
    //                 (F&&)fn,
    //                 (R&&)ranges | unwrap...
    //             ) | algebraic;
    //         }
    //     };
    // }

    // inline namespace functors 
    // {
    //     inline constexpr detail::zip_transform_fn zip_transform{};
    // }
}

#endif