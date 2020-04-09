// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "env.h"
#include "buffer.h"
#include <cassert>
#include <openssl/err.h>

#ifdef BACKTRACE_ON_EXCEPTION
#include <execinfo.h>
#include <dlfcn.h>
#include <cxxabi.h>
#include <inttypes.h>
#endif

#include <sstream>

namespace AmazonCorrettoCryptoProvider {

#ifdef BACKTRACE_ON_EXCEPTION

// This logic uses the execinfo/backtrace() APIs to try to get a native code
// backtrace when something goes wrong. Because this has significant overhead,
// we normally only enable this in debug builds.

// Capture the trace - this runs at the point where the exception is constructed.
void capture_trace(std::vector<void *> &trace) {
    trace.resize(1024);

    // The backtrace function walks the stack and fills a void** buffer with up
    // to the specified number of instruction pointers. The actual trace length is
    // returned, so we then resize the vector to the true size of the trace.

    trace.resize(backtrace(&trace[0], trace.size()));
}

// Format the trace into a string.
// TODO: Defer actually doing this until java asks for the exception string.
void format_trace(std::ostringstream &accum, const std::vector<void *> &trace) {
    accum << " Backtrace:\n";
    char buf[128];
    size_t bufsz = 128;
    char *demangle_buf = (char *)malloc(bufsz);

    for (int i = 0; i < trace.size(); i++) {
        // Print the index of the backtrace frame
        snprintf(buf, sizeof(buf), "%4d   ", i);
        accum << buf;

        // Try to find symbol information for the code address in question
        Dl_info info;
        if (!dladdr(trace[i], &info)) {
            // If we couldn't find a symbol, just print the offset and move on.
            snprintf(buf, sizeof(buf), "%-35s 0x%016" PRIx64 "\n", "???", (uint64_t)trace[i]);
            accum << buf;
            continue;
        }

        const char *image_name = info.dli_fname ? info.dli_fname : "???";

        // Strip off the full path and only print the last component of the library name.
        char *last_slash = strrchr(image_name, '/');
        if (last_slash) {
            image_name = last_slash + 1;
        }

        snprintf(buf, sizeof(buf), "%-35s 0x%016" PRIx64 " ", image_name, (uint64_t)trace[i]);
        accum << buf;

        // Try to demangle the symbol name
        if (!info.dli_sname) {
            accum << "(no matching symbols)\n";
            continue;
        }

        int status;

        // the __cxa_demangle function is a bit complicated - it might
        // realloc() the buffer passed in so we have to be prepared to update
        // our demangle_buf pointer each time we call it.

        char *result = abi::__cxa_demangle(info.dli_sname, demangle_buf, &bufsz, &status);
        if (result) {
            demangle_buf = result;
        }

        if (status == 0) {
            // We successfully demangled the C++ symbol name
            accum << result;
        } else {
            // we failed to demangle the symbol name, so just show the raw symbol
            // (it might be a C symbol or something)
            accum << info.dli_sname;
        }

        // finally tack on the offset from the start of the function
        uint64_t offset = (uint64_t)trace[i] - (uint64_t)info.dli_saddr;
        snprintf(buf, sizeof(buf), " + %" PRIu64 "\n", offset);
        accum << buf;
    }

    free(demangle_buf);
}
#endif

void java_ex::throw_to_java(JNIEnv *env) {
    // Do not try to throw an exception when one is already being thrown.
    if (unlikely(env->ExceptionCheck())) {
        return;
    }

    if (m_java_exception) {
        // Just rethrow the exception as-is
        env->Throw(m_java_exception);
        return;
    }

    jclass ex_class = env->FindClass(m_java_classname);

    if (likely(ex_class != NULL)) {
        std::ostringstream oss;
        if (m_message_cstr) {
            oss << m_message_cstr;
        } else {
            oss << m_message;
        }
#ifdef BACKTRACE_ON_EXCEPTION
        format_trace(oss, m_trace);
#endif

        std::string message = oss.str();

        // If ex_class is null, then java implicitly threw a ClassDefNotFoundError
        int rv = env->ThrowNew(ex_class, message.c_str());
        if (unlikely(rv != 0)) {
            env->FatalError("ThrowNew returned error");
            abort();
        }
    }
    // We can assume that all native error handling has completed
    // by this point, so to ensure there are no errors left in
    // the openssl error queue, we empty it. This avoids accidentally
    // leaving an old error for later error handling to find.
    ERR_clear_error();

    assert(env->ExceptionCheck());
}

java_ex java_ex::from_openssl(const char *ex_class, const char *default_string) {
    return java_ex(ex_class, opensslErrorWithDefault(default_string));
}

void java_ex::rethrow_java_exception(JNIEnv *pEnv) {
    jthrowable throwable = pEnv->ExceptionOccurred();
    if (!throwable) {
        throw_java_ex(EX_ERROR, "rethrow_java_exception called when no exception was pending");
    }
    pEnv->ExceptionClear();
    throw java_ex(throwable);
}

void throw_java_ex(const char *ex_class, const char *message) {
    throw java_ex(ex_class, message);
}

void throw_java_ex(const char *ex_class, const std::string &message) {
    throw java_ex(ex_class, message);
}

void throw_openssl(const char *ex_class, const char *message) {
    throw java_ex::from_openssl(ex_class, message);
}

void throw_openssl(const char *message) {
    throw_openssl(EX_RUNTIME_CRYPTO, message);
}

void throw_openssl() {
    throw_openssl("Unexpected openssl error");
}

void raii_env::get_env_err() {
    std::cerr << "Attempted to use JNI environment while buffer locks were outstanding:" << std::endl;
    buffer_lock_trace();
}

void raii_env::dtor_err() {
    std::cerr << "Attempted to destroy jni context while buffer locks were outstanding:" << std::endl;
    buffer_lock_trace();
    abort();
}

void raii_env::buffer_lock_trace() {
    int n = 0;
    for (jni_borrow *p = m_last_buffer_lock; p; p = p->m_prior_borrow) {
        n++;
        std::cerr << "\t" << p << ": \"" << p->m_trace << "\"" << std::endl;
    }
    std::cerr << "End trace (" << n << " locks)" << std::endl;

    std::vector<void *> trace;
    AmazonCorrettoCryptoProvider::capture_trace(trace);

    std::ostringstream oss;
    AmazonCorrettoCryptoProvider::format_trace(oss, trace);

    std::cerr << oss.str();
}
}
