// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ACCP_ENV_H
#define ACCP_ENV_H 1

#include "config.h"
#include "compiler.h"
#include "util.h"
#include <stdint.h>
#include <iostream>
#include <cstdlib> // abort()
#include <cassert>
#include <vector>
#include <sstream>
#include <memory>

#ifdef HAVE_IS_TRIVIALLY_COPYABLE
#include <type_traits>
#endif

#ifdef EXTRA_TEST_ASSERT
#include <openssl/err.h>
#endif

#ifndef UINT64_MAX
#define UINT64_MAX (~((uint64_t) 0))
#endif

namespace AmazonCorrettoCryptoProvider {
    void capture_trace(std::vector<void *> &trace) COLD;
    void format_trace(std::ostringstream &, const std::vector<void *> &trace) COLD;

#ifndef BACKTRACE_ON_EXCEPTION
    inline void capture_trace(std::vector<void *> &trace) {}
    inline void format_trace(std::ostringstream &, const std::vector<void *> &trace) {}
#endif

/**
 * C++ representation of a Java exception to be thrown. Constructing and
 * C++-throwing java_ex objects does not result in any JNI calls, and can
 * therefore be done while buffer locks are held.
 */
class java_ex {
    private:
        // When an exception is thrown from java, we remove it from the pending-exception
        // state and stash it here, thus allowing us to make other java calls while unwinding the stack.
        // In this case this field will be non-null and contain the actual exception object to
        // rethrow
        jthrowable m_java_exception;

        const char *m_java_classname;
        const std::string m_message;
        const char *m_message_cstr;
#ifdef BACKTRACE_ON_EXCEPTION
        std::vector<void *> m_trace;
        void capture_trace() COLD { AmazonCorrettoCryptoProvider::capture_trace(m_trace); }
#else
        void capture_trace() {}
#endif

    public:
        java_ex(jthrowable exception) COLD
            : m_java_exception(exception), m_java_classname(nullptr), m_message(), m_message_cstr("")
        { }

        java_ex(const char *java_classname, const char *message) COLD
            : m_java_exception(nullptr), m_java_classname(java_classname), m_message(), m_message_cstr(message)
        { capture_trace(); }

        java_ex(const char *java_classname, const std::string &message) COLD
            : m_java_exception(nullptr), m_java_classname(java_classname), m_message(message), m_message_cstr(nullptr)
        { capture_trace(); }

        /**
         * Constructs an exception based on the openssl error code.
         * Arguments:
         *  ex_class - the classname of the exception to throw
         *  default_string - A string to use for the exception message if the openssl error is unavailable
         */
        static java_ex from_openssl(const char *ex_class, const char *default_string) COLD;

        /**
         * Throws a java_ex that represents the fact that a Java exception has _already_ been thrown.
         * The java exception will be removed from the JVM's pending exception state, so that JNI
         * calls can be safely performed while unwinding the stack.
         *
         * Normally you should call raii_env.rethrow_java_exception instead; the variant on raii_env
         * checks the pending exception flag first.
         */
        static void rethrow_java_exception(JNIEnv *pEnv) NORETURN COLD;

        /**
         * Sets the pending JNI exception based on this java_ex object.
         *
         * All information in the java_ex object is _copied_ into the java exception
         * state, so the java_ex object can be immediately destroyed afterward.
         *
         * Note that this takes a raw JNIEnv pointer rather than an raii_env, to emphasize
         * that this should be called at the top level JNI entry point only.
         */
        void throw_to_java(JNIEnv *env) COLD;
};

// Equivalent to throw java_ex(...), but the actual code to throw the exception is pushed
// well out-of-line for possibly slightly better performance.
void throw_java_ex(const char *ex_class, const char *message) NORETURN COLD;
void throw_java_ex(const char *ex_class, const std::string &message) NORETURN COLD;

// Equivalent to throw java_ex::from_openssl(ex_class, message)
void throw_openssl(const char *ex_class, const char *message) NORETURN COLD;
// Equivalent to throw_openssl(EX_RUNTIME_CRYPTO, message)
void throw_openssl(const char *message) NORETURN COLD;
// Equivalent to throw_openssl(generic default message)
void throw_openssl() NORETURN COLD;

// Wrapper for openssl calls that shouldn't normally fail; if this fails a generic exception
// will be thrown.
template<typename T>
T check_openssl_impl(T expr, const char *errstr) {
    if (unlikely(!expr)) {
        throw_openssl(errstr);
    }

    return expr;
}
#define CHECK_OPENSSL(expr) check_openssl_impl(expr, "Unexpected error in openssl; expression: " #expr);

/**
 * A C++ wrapper over the JNIEnv that tracks outstanding buffer locks (if done
 * via the borrow API) and aborts if illegal calls are made while a buffer lock
 * is held
 *
 * Generally, you will construct an raii_env object immediately after entering the
 * C++ side, and pass references to it down to any subsequent helper methods to ensure
 * buffer lock tracking is properly performed.
 *
 * TODO: Find a better name for this. I don't want to use 'context' due to confusion
 * with hash contexts.
 */
class raii_env {
    private:
        JNIEnv *m_env;

        class jni_borrow *m_last_buffer_lock;

        void buffer_lock_trace() COLD;

        void get_env_err() COLD;
        void dtor_err() COLD NORETURN;

        friend class jni_borrow;

        raii_env(const raii_env &) DELETE_IMPLICIT;
        raii_env &operator=(const raii_env &) DELETE_IMPLICIT;
        raii_env() DELETE_IMPLICIT;
    public:
        void fatal_error(const char *why) NORETURN COLD {
            m_env->FatalError(why);
            while (true) {} // unreachable, silences noreturn warning
        }

        /**
         * If a java exception is pending, throws a corresponding java_ex.
         */
        void rethrow_java_exception() const __attribute__((always_inline)) {
            if (unlikely(const_cast<raii_env *>(this)->get_env()->ExceptionCheck())) {
                java_ex::rethrow_java_exception(m_env);
            }
        }

        bool is_locked() const __attribute__((always_inline)) {
            return !!m_last_buffer_lock;
        }

        raii_env(JNIEnv *env)
        : m_env(env), m_last_buffer_lock(nullptr)
        {
        }

        JNIEnv *operator->() const __attribute__((always_inline)) {
            return get_env();
        }

        JNIEnv *get_env() const __attribute__((always_inline)) {
            if (unlikely(is_locked())) {
                // We put the error message code out of line to ensure the fast path can be inlined
                const_cast<raii_env *>(this)->get_env_err();
                return nullptr; // cause a NPE at the actual site of usage
            }

            return m_env;
        }

        ~raii_env() {
            if (unlikely(is_locked())) {
                // We put the error message code out of line to ensure the fast path can be inlined
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
// EXTRA_TEST_ASSERT
#endif
        }
};

// Allows us to use C++ RAII for JNI strings.
class jni_string {
private:
    jstring java_str;
    raii_env *pRaiiEnv;
public:
    const char *native_str;

    operator const char *() const {
        return native_str;
    }

    jni_string(raii_env &env, jstring java_str) {
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


    ~jni_string() {
        (*pRaiiEnv)->ReleaseStringUTFChars(java_str, native_str);
    }
};

// This is a custom allocator for use with std:: classes which ensures
// that all memory is initialized to zero prior to use and prior to freeing.
// http://en.cppreference.com/w/cpp/concept/Allocator
template<class T>
struct SecureAlloc {
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    template<class U> struct rebind { typedef SecureAlloc<U> other; };

    SecureAlloc() noexcept { }
    template<class U> SecureAlloc(const SecureAlloc<U>&) noexcept {
    }


    T* allocate(std::size_t n) {
      if (n > SIZE_MAX / sizeof(T)) {
        throw std::bad_alloc();
      }
      T* result = static_cast<T*>(::operator new(n * sizeof(T)));
      if (result) {
        return result;
      } else {
        throw std::bad_alloc();
      }
    }

    size_t max_size() const noexcept {
      return SIZE_MAX / sizeof(T);
    }

    T* address(T& x) const noexcept {
      return std::allocator<T>::address(x);
    }

    const T* address(const T& x) const noexcept {
      return std::allocator<T>::address(x);
    }

    void deallocate(T* p, std::size_t n) noexcept {
      if (p != nullptr && n > 0) {
        secureZero(p, n * sizeof(T));
      }
      ::operator delete(p);
    }

    void construct(T* p, const T& val) {
      new(p) T(val);
    }

    void destroy(T* p) noexcept {
      p->~T();
    }
};

template<class T, class U>
bool operator==(const SecureAlloc<T>&, const SecureAlloc<U>&) {
  return true;
}
template<class T, class U>
bool operator!=(const SecureAlloc<T>&, const SecureAlloc<U>&) {
  return false;
}


} // namespace AmazonCorrettoCryptoProvider

#endif
