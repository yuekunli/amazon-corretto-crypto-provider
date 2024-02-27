// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ACCP_ENV_H
#define ACCP_ENV_H 1

#include "compiler.h"
#include "util.h"
#include <cassert>
#include <cstdlib> // abort()
#include <iostream>
#include <memory>
#include <sstream>
#include <stdint.h>
#include <vector>
#include <string>
#include <limits>

#ifdef HAVE_IS_TRIVIALLY_COPYABLE
#include <type_traits>
#endif

#ifdef EXTRA_TEST_ASSERT
#include <openssl/err.h>
#endif

namespace AmazonCorrettoCryptoProvider {
void capture_trace(std::vector<void*>& trace) COLD;
void format_trace(std::ostringstream&, const std::vector<void*>& trace) COLD;

#ifndef BACKTRACE_ON_EXCEPTION
inline void capture_trace(std::vector<void*>& trace) { }
inline void format_trace(std::ostringstream&, const std::vector<void*>& trace) { }
#endif


class java_ex {
private:
    jthrowable m_java_exception;

    const char* m_java_classname;
    const std::string m_message;

#ifdef BACKTRACE_ON_EXCEPTION
    std::vector<void*> m_trace;
    void capture_trace() COLD { AmazonCorrettoCryptoProvider::capture_trace(m_trace); }
#else
    void capture_trace() { }
#endif

public:
    java_ex(jthrowable exception) COLD : m_java_exception(exception), m_java_classname(nullptr), m_message() { }


    java_ex(const char* java_classname, const char* message) COLD : m_java_exception(nullptr),
                                                                    m_java_classname(java_classname),
                                                                    m_message(std::string(message))
    {
        capture_trace();
    }

    java_ex(const char* java_classname, const std::string& message) COLD : m_java_exception(nullptr),
                                                                           m_java_classname(java_classname),
                                                                           m_message(message)
    {
        capture_trace();
    }

    static java_ex from_openssl(const char* ex_class, const char* default_string) COLD;

    NORETURN1 static void rethrow_java_exception(JNIEnv* pEnv) NORETURN2 COLD;

    void throw_to_java(JNIEnv* env) COLD;
};


NORETURN1 void throw_java_ex(const char* ex_class, const char* message) NORETURN2 COLD;
NORETURN1 void throw_java_ex(const char* ex_class, const std::string& message) NORETURN2 COLD;


NORETURN1 void throw_openssl(const char* ex_class, const char* message) NORETURN2 COLD;

NORETURN1 void throw_openssl(const char* message) NORETURN2 COLD;

NORETURN1 void throw_openssl() NORETURN2 COLD;


template <typename T> T check_openssl_impl(T expr, const char* errstr)
{
    if (unlikely(!expr)) {
        throw_openssl(errstr);
    }

    return expr;
}
#define CHECK_OPENSSL(expr) check_openssl_impl(expr, "Unexpected error in openssl; expression: " #expr);


class raii_env {
private:
    JNIEnv* m_env;

    class jni_borrow* m_last_buffer_lock;

    void buffer_lock_trace() COLD;

    void get_env_err() COLD;
    NORETURN1 void dtor_err() COLD NORETURN2;

    friend class jni_borrow;

    raii_env(const raii_env&) DELETE_IMPLICIT;
    raii_env& operator=(const raii_env&) DELETE_IMPLICIT;
    raii_env() DELETE_IMPLICIT;

public:
    NORETURN1 void fatal_error(const char* why) NORETURN2 COLD
    {
        m_env->FatalError(why);
        while (true) { }
    }


    FORCE_INLINE1 void rethrow_java_exception() const FORCE_INLINE2
    {
        if (unlikely(const_cast<raii_env*>(this)->get_env()->ExceptionCheck())) {
            java_ex::rethrow_java_exception(m_env);
        }
    }

    FORCE_INLINE1 bool is_locked() const FORCE_INLINE2 { return !!m_last_buffer_lock; }

    raii_env(JNIEnv* env)
        : m_env(env)
        , m_last_buffer_lock(nullptr)
    {
    }

    FORCE_INLINE1 JNIEnv* operator->() const FORCE_INLINE2 { return get_env(); }

    FORCE_INLINE1 JNIEnv* get_env() const FORCE_INLINE2
    {
        if (unlikely(is_locked())) {
            const_cast<raii_env*>(this)->get_env_err();
            return nullptr; // cause a NPE at the actual site of usage
        }

        return m_env;
    }

    ~raii_env()
    {
        if (unlikely(is_locked())) {
            dtor_err();
            abort();
        }
#ifdef EXTRA_TEST_ASSERT
        // This check is very expensive when there are lots of threads and /should/ be NOP.
        // So we add it only for test builds and abort/fail the test if there are any unhandled errors.
        // We also manually loop over the errors rather than using drainOpensslErrors so we can
        // explicitly log them all for easier debugging.
        bool errorFound = false;
        const char* file;
        int line;
        unsigned long unhandledError = ERR_get_error_line(&file, &line);
        while (unhandledError) {
            errorFound = true;
            std::cerr << "Found unhandled openssl error: " << formatOpensslError(unhandledError, "NO_TEXT");
            std::cerr << " @ " << file << ":" << line << std::endl;
            unhandledError = ERR_get_error_line(&file, &line);
        }
        if (errorFound) {
            abort();
        }

#endif  // EXTRA_TEST_ASSERT

    }
};


class jni_string {
private:
    jstring java_str;
    raii_env* pRaiiEnv;

public:
    const char* native_str;

    operator const char*() const { return native_str; }

    jni_string(raii_env& env, jstring java_str)
    {
        this->java_str = java_str;
        this->pRaiiEnv = &env;

        if (unlikely(!java_str)) {
            throw_java_ex(EX_NPE, "Null string passed to java");
        }

        native_str = (*pRaiiEnv)->GetStringUTFChars(java_str, NULL);

        if (unlikely(!native_str)) {
            throw_java_ex(EX_OOM, "Failed to access string contents");
        }
    }

    ~jni_string() { (*pRaiiEnv)->ReleaseStringUTFChars(java_str, native_str); }
};


template <class T> 
struct SecureAlloc {
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    template <class U> struct rebind {
        typedef SecureAlloc<U> other;
    };

    SecureAlloc() noexcept { }
    template <class U> SecureAlloc(const SecureAlloc<U>&) noexcept { }

    T* allocate(std::size_t n)
    {
        if (n > (std::numeric_limits<size_t>::max() / sizeof(T))) {
            throw std::bad_alloc();
        }
        T* result = static_cast<T*>(::operator new(n * sizeof(T)));
        if (result) {
            return result;
        } else {
            throw std::bad_alloc();
        }
    }

    size_t max_size() const noexcept { return std::numeric_limits<size_t>::max() / sizeof(T); }

    T* address(T& x) const noexcept { return std::allocator<T>::address(x); }

    const T* address(const T& x) const noexcept { return std::allocator<T>::address(x); }

    void deallocate(T* p, std::size_t n) noexcept
    {
        if (p != nullptr && n > 0) {
            secureZero(p, n * sizeof(T));
        }
        ::operator delete(p);
    }

    void construct(T* p, const T& val) { new (p) T(val); }

    void destroy(T* p) noexcept { p->~T(); }
};

template <class T, class U> bool operator==(const SecureAlloc<T>&, const SecureAlloc<U>&) { return true; }
template <class T, class U> bool operator!=(const SecureAlloc<T>&, const SecureAlloc<U>&) { return false; }

} // namespace AmazonCorrettoCryptoProvider

#endif
