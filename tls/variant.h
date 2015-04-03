#include <type_traits>
#include <utility>
#include <cassert>
#include <cstddef>
#include <stdexcept>

namespace funtls { namespace tls {

namespace detail {

template<int count, typename Candidate, typename... Ts>
struct get_index_helper;

template<int count, typename Candidate, typename T>
struct get_index_helper<count, Candidate, T> {
    static constexpr int value = std::is_same<Candidate, T>::value ? count : -1;
};

template<int count, typename Candidate, typename T, typename... Ts>
struct get_index_helper<count, Candidate, T, Ts...> {
    static constexpr int value = std::is_same<Candidate, T>::value ? count : get_index_helper<count+1,Candidate,Ts...>::value;
};

template<typename Candidate, typename... Ts>
constexpr int get_index() {
    static_assert(get_index_helper<0, Candidate, Ts...>::value!= -1, "Trying to construct union with unknown type");
    return get_index_helper<0, Candidate, Ts...>::value;
}

template<typename... Ts>
struct max_size;

template<typename T>
struct max_size<T>
    : public std::integral_constant<size_t, sizeof(T)> {};

template<typename T, typename... Ts>
struct max_size<T, Ts...>
    : public std::integral_constant<size_t, (sizeof(T) > max_size<Ts...>::value ? sizeof(T) : max_size<Ts...>::value)> {};

template<typename... Ts>
struct invoke_helper;

template<typename T>
struct invoke_helper<T> {
    template<typename F>
    static void invoke(void* storage, int type, F f) {
        assert(type == 0);
        f(*reinterpret_cast<T*>(storage));
    }
};

template<typename T, typename... Ts>
struct invoke_helper<T, Ts...> {
    template<typename F>
    static void invoke(void* storage, int type, F f) {
        if (!type) {
            f(*reinterpret_cast<T*>(storage));
        } else {
            invoke_helper<Ts...>::invoke(storage, type - 1, f);
        }
    }
};

template<typename... Ts, typename F>
void invoke(void* storage, int type, F f)
{
    assert(type >= 0);
    invoke_helper<Ts...>::invoke(storage, type, f);
}

} // namespace detail

template<typename... Ts>
class variant {
public:
    // , typename std::enable_if<!std::is_same<typename std::decay<U>::type, variant>::value>::type* =0
    template<typename U>
    variant(U&& the_u) : type(detail::get_index<typename std::decay<U>::type, Ts...>()) {
        assert(type >= 0);
        new (&storage) typename std::decay<U>::type(std::forward<U>(the_u));
    }

    ~variant() {
        destroy();
    }

    variant(const variant& other) : type(invalid_type) {
        copy(other);
    }

    variant(variant&& other) : type(invalid_type) {
        if (other.type != invalid_type) {
            detail::invoke<Ts...>(&storage, other.type, move_helper(&other.storage));
            type = other.type;
            other.type = invalid_type;
        }
    }

    variant& operator=(const variant& other) {
        if (this != &other) {
            destroy();
            copy(other);
        }
        return *this;
    }

    // Not implemented yet
    variant& operator=(variant&& other) = delete;

    template<typename F>
    void invoke(F f) {
        detail::invoke<Ts...>(&storage, type, f);
    }

    template<typename F>
    void invoke(F f) const {
        // Lazy...
        detail::invoke<Ts...>(const_cast<void*>(static_cast<const void*>(&storage)), type, f);
    }

    template<typename U>
    U& get() {
        int wanted_type = detail::get_index<typename std::decay<U>::type, Ts...>();
        if (type != wanted_type) {
            throw std::logic_error("Invalid cast to type " + std::to_string(wanted_type) + " from " + std::to_string(type));
        }
        return *reinterpret_cast<U*>(&storage);
    }

private:
    static constexpr size_t size = detail::max_size<Ts...>::value;
    static constexpr int    invalid_type = -1;
    using                   storage_t = typename std::aligned_storage<size>::type;
    int                     type;
    storage_t               storage;

    struct destroy_helper {
        template<typename T>
            void operator()(T& t) {
                t.~T();
            }
    };

    void destroy() {
        if (type != invalid_type) {
            detail::invoke<Ts...>(&storage, type, destroy_helper());
            type = invalid_type;
        }
    }

    struct move_helper {
        move_helper(void* to_move) : to_move(to_move) {}
        template<typename U>
        void operator()(U& u) {
            new (&u) U(std::move(*reinterpret_cast<U*>(to_move)));
        }
        void* to_move;
    };

    struct copy_helper {
        copy_helper(const void* to_copy) : to_copy(to_copy) {}
        template<typename U>
        void operator()(U& u) {
            new (&u) U(*reinterpret_cast<const U*>(to_copy));
        }
        const void* to_copy;
    };

    void copy(const variant& other) {
        assert(this != &other);
        assert(type == invalid_type);
        if (other.type != invalid_type) {
            detail::invoke<Ts...>(&storage, other.type, copy_helper(&other.storage));
        }
        type = other.type; // only assign type after copy is sucessful
    }

};

} } // namespace funtls::tls
