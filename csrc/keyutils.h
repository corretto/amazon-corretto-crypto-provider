// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef KEYUTILS_H
#define KEYUTILS_H 1

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "util.h"
#include "env.h"

namespace AmazonCorrettoCryptoProvider {

class EvpKeyContext {
public:
    EvpKeyContext()
        : digestCtx_(NULL), keyCtx_(NULL), key_(NULL) {}

    virtual ~EvpKeyContext() {
        if (digestCtx_) {
            EVP_MD_CTX_destroy(digestCtx_);
        }
        if (keyCtx_) {
            EVP_PKEY_CTX_free(keyCtx_);
        }
        if (key_) {
            EVP_PKEY_free(key_);
        }
    }

    EVP_MD_CTX* getDigestCtx() const { return digestCtx_; }
    EVP_PKEY_CTX* getKeyCtx() const { return keyCtx_; }
    EVP_PKEY* getKey() const { return key_; }

    // If there was an old ctx, it is freed
    EVP_MD_CTX* setDigestCtx(EVP_MD_CTX* digestCtx) {
        if (digestCtx_) {
            EVP_MD_CTX_destroy(digestCtx_);
        }
        digestCtx_ = digestCtx;
        return digestCtx_;
    }

    // If there was an old ctx, it is freed
    EVP_PKEY_CTX* setKeyCtx(EVP_PKEY_CTX* keyCtx) {
        if (keyCtx_) {
            EVP_PKEY_CTX_free(keyCtx_);
        }

        keyCtx_ = keyCtx;
        return keyCtx_;
    }

    // If there was an old key, it is freed
    EVP_PKEY* setKey(EVP_PKEY* key) {
        if (key_) {
            EVP_PKEY_free(key_);
        }
        key_ = key;
        return key_;
    }

    // Allocates a copy of this object on the heap and zeros
    // the pointers thus moving ownership of the contained objects
    // to the new copy of this EvpKeyContext.
    EvpKeyContext* moveToHeap() {
        EvpKeyContext* result = new EvpKeyContext();
        result->setKey(key_);
        result->setDigestCtx(digestCtx_);
        result->setKeyCtx(keyCtx_);

        // Zero our pointers so we don't free anything upon destruction
        digestCtx_ = NULL;
        keyCtx_ = NULL;
        key_ = NULL;
        return result;
    }

private:    
    EVP_MD_CTX* digestCtx_;
    EVP_PKEY_CTX* keyCtx_;
    EVP_PKEY* key_;

    // Disable copy & copy-assignment
    EvpKeyContext(const EvpKeyContext&) DELETE_IMPLICIT;
    EvpKeyContext& operator=(const EvpKeyContext&) DELETE_IMPLICIT;
};

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der, const int derLen, const bool checkPrivateKey, const char* javaExceptionClass);
EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass);
bool checkKey(EVP_PKEY* key);

class raii_cipher_ctx {
    private:
        EVP_CIPHER_CTX* m_ctx;
        bool m_owning;

    public:
        raii_cipher_ctx() 
        : m_ctx(nullptr), m_owning(false)
        {
        }

        void clean() {
            if (m_ctx && m_owning) {
                EVP_CIPHER_CTX_free(m_ctx);
            }
        }

        ~raii_cipher_ctx() {
            clean();
        }

        void init() {
            move(EVP_CIPHER_CTX_new());
        }

        void borrow(EVP_CIPHER_CTX *ctx) {
            clean();
            m_owning = false;
            m_ctx = ctx;
        }

        void move(EVP_CIPHER_CTX *ctx) {
            clean();
            m_owning = true;
            m_ctx = ctx;
        }

        operator EVP_CIPHER_CTX*() {
            return m_ctx;
        }

        operator const EVP_CIPHER_CTX*() const {
            return m_ctx;
        }

        EVP_CIPHER_CTX& operator*() {
            return *m_ctx;
        }

        const EVP_CIPHER_CTX& operator*() const {
            return *m_ctx;
        }

        EVP_CIPHER_CTX* take() {
            EVP_CIPHER_CTX* result = m_ctx;
            m_ctx = nullptr;
            return result;
        }
};

}

#endif
