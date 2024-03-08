// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef KEYUTILS_H
#define KEYUTILS_H 1

#include "auto_free.h"
#include "env.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// Contains utility methods and classes for dealing with keys or openssl structures.
// Unlike util.h, this is intended to capture high-level logic with more internal dependencies.

namespace AmazonCorrettoCryptoProvider {

// This class should generally not be used for new development
// as it has been replaced by the *_auto classes in auto_free.h
// The only time this class should be used is when you *need* to keep various EVP objects together.
// The only currently known *good* use for this class is tracking state when signing/verifying data.
//
// Since all but EVP_PKEY are stateful and likely to mutate while being used, this class is not threadsafe.
class EvpKeyContext {
public:
    EvpKeyContext() { } // Since we explicitly deleted constructors, the implicit one isn't generated for us.
    EVP_MD_CTX* getDigestCtx() { return digestCtx_.get(); }
    EVP_PKEY_CTX* getKeyCtx() { return keyCtx_.get(); }
    EVP_PKEY* getKey() { return key_.get(); }
    EVP_PKEY* get1Key()
    {
        EVP_PKEY_up_ref(key_);
        return getKey();
    }
    EVP_PKEY** getKeyPtr() { return key_.getAddressOfPtr(); }

    // If there was an old ctx, it is freed
    EVP_MD_CTX* setDigestCtx(EVP_MD_CTX* digestCtx)
    {
        digestCtx_.set(digestCtx);
        return getDigestCtx();
    }

    // If there was an old ctx, it is freed
    EVP_PKEY_CTX* setKeyCtx(EVP_PKEY_CTX* keyCtx)
    {
        keyCtx_.set(keyCtx);
        return getKeyCtx();
    }

    // If there was an old key, it is freed
    EVP_PKEY* setKey(EVP_PKEY* key)
    {
        key_.set(key);
        return getKey();
    }

    // Allocates a copy of this object on the heap and zeros
    // the pointers thus moving ownership of the contained objects
    // to the new copy of this EvpKeyContext.
    EvpKeyContext* moveToHeap()
    {
        EvpKeyContext* result = new EvpKeyContext();
        // Move the pointers and ownership to the new object.
        result->setKey(key_.take());
        result->setDigestCtx(digestCtx_.take());
        result->setKeyCtx(keyCtx_.take());

        return result;
    }

private:
    EVP_MD_CTX_auto digestCtx_;
    EVP_PKEY_CTX_auto keyCtx_;
    EVP_PKEY_auto key_;

    // Disable copy & copy-assignment
    EvpKeyContext(const EvpKeyContext&) DELETE_IMPLICIT;
    EvpKeyContext& operator=(const EvpKeyContext&) DELETE_IMPLICIT;
};

EVP_PKEY* der2EvpPrivateKey(
    const unsigned char* der, const int derLen, const bool checkPrivateKey, const char* javaExceptionClass);
EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass);
bool checkKey(const EVP_PKEY* key);
static bool inline BN_null_or_zero(const BIGNUM* bn) { return nullptr == bn || BN_is_zero(bn); }

class raii_cipher_ctx {
private:
    EVP_CIPHER_CTX* m_ctx;
    bool m_owning;

public:
    raii_cipher_ctx()
        : m_ctx(nullptr)
        , m_owning(false)
    {
    }

    void clean()
    {
        if (m_ctx && m_owning) {
            EVP_CIPHER_CTX_free(m_ctx);
        }
    }

    ~raii_cipher_ctx() { clean(); }

    void init() { move(EVP_CIPHER_CTX_new()); }

    void borrow(EVP_CIPHER_CTX* ctx)
    {
        clean();
        m_owning = false;
        m_ctx = ctx;
    }

    void move(EVP_CIPHER_CTX* ctx)
    {
        clean();
        m_owning = true;
        m_ctx = ctx;
    }

    operator EVP_CIPHER_CTX*() { return m_ctx; }

    operator const EVP_CIPHER_CTX*() const { return m_ctx; }

    EVP_CIPHER_CTX& operator*() { return *m_ctx; }

    const EVP_CIPHER_CTX& operator*() const { return *m_ctx; }

    EVP_CIPHER_CTX* take()
    {
        EVP_CIPHER_CTX* result = m_ctx;
        m_ctx = nullptr;
        return result;
    }
};

const EVP_MD* digestFromJstring(raii_env& env, jstring digestName);

// The generated RSA structure will own n and d.
RSA* RSA_new_private_key_no_e(BIGNUM* n, BIGNUM* d);

}

#endif
