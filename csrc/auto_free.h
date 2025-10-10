// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AUTO_FREE_H
#define AUTO_FREE_H

#include "env.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

// These macros allow us to easily defined stack managed versions of various Openssl structures.
// Some objects will require custom implementations (such as unsigned char* and BN).
// In order for this to work the following methods must be defined:
// FOO_free(FOO*)

#define CLASSNAME(name) CONCAT2(name, _auto)
#define PTR_NAME(name)  CONCAT2(p, name)
#define AUTO_CONSTRUCTORS(name)                                                                                        \
    /* Do not allow implicit copy constructors */                                                                      \
    CLASSNAME(name)                                                                                                    \
    (const CLASSNAME(name)&) = delete;                                                                                 \
    CLASSNAME(name)& operator=(const CLASSNAME(name)&) = delete;                                                       \
    /* Move semantics */                                                                                               \
    CLASSNAME(name)& operator=(CLASSNAME(name) && other)                                                               \
    {                                                                                                                  \
        move(other);                                                                                                   \
        return *this;                                                                                                  \
    }                                                                                                                  \
    CLASSNAME(name)                                                                                                    \
    (CLASSNAME(name) && other) { move(other); }

#define OPENSSL_auto(name)                                                                                             \
    class CLASSNAME(name) {                                                                                            \
    private:                                                                                                           \
        name* PTR_NAME(name);                                                                                          \
        void move(CLASSNAME(name) & other) { set(other.take()); }                                                      \
                                                                                                                       \
    public:                                                                                                            \
        AUTO_CONSTRUCTORS(name)                                                                                        \
        CLASSNAME(name)() { PTR_NAME(name) = NULL; }                                                                   \
        static CLASSNAME(name) from(name* ptr)                                                                         \
        {                                                                                                              \
            CLASSNAME(name) tmp;                                                                                       \
            tmp.PTR_NAME(name) = ptr;                                                                                  \
            return tmp;                                                                                                \
        }                                                                                                              \
        ~CLASSNAME(name)() { clear(); }                                                                                \
        bool isInitialized() { return !!PTR_NAME(name); }                                                              \
        bool set(name* ptr)                                                                                            \
        {                                                                                                              \
            clear();                                                                                                   \
            PTR_NAME(name) = ptr;                                                                                      \
            return !!ptr;                                                                                              \
        }                                                                                                              \
        name* take()                                                                                                   \
        {                                                                                                              \
            name* tmpPtr = PTR_NAME(name);                                                                             \
            PTR_NAME(name) = NULL;                                                                                     \
            return tmpPtr;                                                                                             \
        }                                                                                                              \
        void releaseOwnership() { PTR_NAME(name) = NULL; }                                                             \
        void clear()                                                                                                   \
        {                                                                                                              \
            CONCAT2(name, _free)(PTR_NAME(name));                                                                       \
            PTR_NAME(name) = NULL;                                                                                     \
        }                                                                                                              \
        name* operator->() { return *this; }                                                                           \
        operator name*()                                                                                               \
        {                                                                                                              \
            if (!PTR_NAME(name)) {                                                                                     \
                abort();                                                                                               \
            }                                                                                                          \
            return PTR_NAME(name);                                                                                     \
        }                                                                                                              \
        name* get() { return PTR_NAME(name); }                                                                         \
        name** getAddressOfPtr() { return &PTR_NAME(name); }                                                           \
    }

OPENSSL_auto(RSA);
OPENSSL_auto(PKCS8_PRIV_KEY_INFO);
OPENSSL_auto(EC_GROUP);
OPENSSL_auto(EC_POINT);
OPENSSL_auto(EC_KEY);
OPENSSL_auto(BN_CTX);
OPENSSL_auto(EVP_MD_CTX);
OPENSSL_auto(EVP_PKEY);
OPENSSL_auto(EVP_PKEY_CTX);

class OPENSSL_buffer_auto {
private:
    OPENSSL_buffer_auto(const OPENSSL_buffer_auto&) DELETE_IMPLICIT;
    OPENSSL_buffer_auto& operator=(const OPENSSL_buffer_auto&) DELETE_IMPLICIT;

public:
    unsigned char* buf;

    explicit OPENSSL_buffer_auto()
        : buf(NULL)
    {
    }

    explicit OPENSSL_buffer_auto(size_t buf_size)
        : buf((unsigned char*)OPENSSL_malloc(buf_size))
    {
    }

    virtual ~OPENSSL_buffer_auto() { OPENSSL_free(buf); }

    operator unsigned char*() { return buf; }

    operator unsigned char*() const { return buf; }

    unsigned char** operator&() { return &buf; }

    operator jbyte*() { return reinterpret_cast<jbyte*>(buf); }

    operator jbyte*() const { return reinterpret_cast<jbyte*>(buf); }
};

#undef AUTO_CONSTRUCTORS
#undef CLASSNAME
#undef OPENSSL_auto
#endif
