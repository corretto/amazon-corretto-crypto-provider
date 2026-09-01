// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/aead.h>
#include <openssl/err.h>

#define KEY_LEN_AES128 16
#define KEY_LEN_AES256 32
#define GCM_SIV_NONCE_LENGTH 12
#define GCM_SIV_TAG_LENGTH 16

#define EX_BADTAG "javax/crypto/AEADBadTagException"

using namespace AmazonCorrettoCryptoProvider;

static EVP_AEAD_CTX* createAeadCtx(raii_env& env, java_buffer keyBuf)
{
    const EVP_AEAD* aead;
    switch (keyBuf.len()) {
    case KEY_LEN_AES128:
        aead = EVP_aead_aes_128_gcm_siv();
        break;
    case KEY_LEN_AES256:
        aead = EVP_aead_aes_256_gcm_siv();
        break;
    default:
        throw java_ex(EX_RUNTIME_CRYPTO, "Unsupported key length for AES-GCM-SIV");
    }

    SecureBuffer<uint8_t, KEY_LEN_AES256> keybuf;
    keyBuf.get_bytes(env, keybuf.buf, 0, keyBuf.len());

    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, keybuf.buf, keyBuf.len(), GCM_SIV_TAG_LENGTH);
    if (unlikely(!ctx)) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to create AES-GCM-SIV AEAD context");
    }
    return ctx;
}

// Creates a new EVP_AEAD_CTX for the given key and returns its pointer.
// The caller is responsible for freeing it via releaseAeadCtx.
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSivSpi_nCreateContext(
    JNIEnv* pEnv, jclass, jbyteArray keyArray)
{
    try {
        raii_env env(pEnv);
        java_buffer keyBuf = java_buffer::from_array(env, keyArray);
        EVP_AEAD_CTX* ctx = createAeadCtx(env, keyBuf);
        return reinterpret_cast<jlong>(ctx);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

// Encrypts plaintext with AES-GCM-SIV. Ciphertext = plaintext || tag (16 bytes).
// Returns: number of bytes written to outputArray, or -1 on error.
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSivSpi_nSeal(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jboolean sameKey,
    jlongArray ctxOut,
    jbyteArray keyArray,
    jbyteArray nonceArray,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jbyteArray outputArray,
    jint outputOffset,
    jbyteArray aadArray,
    jint aadLen)
{
    try {
        raii_env env(pEnv);

        // Create all java_buffers before any borrows
        java_buffer nonceBuf = java_buffer::from_array(env, nonceArray);
        java_buffer inputBuf = java_buffer::from_array(env, inputArray, inputOffset, inputLen);
        java_buffer outputBuf = java_buffer::from_array(env, outputArray, outputOffset);
        java_buffer aadBuf;
        if (aadLen > 0) {
            aadBuf = java_buffer::from_array(env, aadArray, 0, aadLen);
        }

        EVP_AEAD_CTX* ctx;
        bool ownsCtx = false;

        if (ctxPtr != 0 && sameKey == JNI_TRUE) {
            ctx = reinterpret_cast<EVP_AEAD_CTX*>(ctxPtr);
        } else {
            java_buffer keyBuf = java_buffer::from_array(env, keyArray);
            ctx = createAeadCtx(env, keyBuf);
            ownsCtx = true;
        }

        size_t out_len = 0;
        bool success;

        {
            jni_borrow nonce(env, nonceBuf, "nonce");
            jni_borrow input(env, inputBuf, "input");
            jni_borrow output(env, outputBuf, "output");

            if (aadLen > 0) {
                jni_borrow aad(env, aadBuf, "aad");
                success = EVP_AEAD_CTX_seal(ctx,
                    output.data(),
                    &out_len,
                    outputBuf.len(),
                    nonce.data(),
                    GCM_SIV_NONCE_LENGTH,
                    input.data(),
                    inputLen,
                    aad.data(),
                    aadLen);
            } else {
                success = EVP_AEAD_CTX_seal(ctx,
                    output.data(),
                    &out_len,
                    outputBuf.len(),
                    nonce.data(),
                    GCM_SIV_NONCE_LENGTH,
                    input.data(),
                    inputLen,
                    nullptr,
                    0);
            }
        }

        if (unlikely(!success)) {
            if (ownsCtx) {
                EVP_AEAD_CTX_free(ctx);
            }
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "AES-GCM-SIV seal failed");
        }

        if (ownsCtx) {
            if (ctxOut != nullptr) {
                jlong tmpPtr = reinterpret_cast<jlong>(ctx);
                pEnv->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
            } else {
                EVP_AEAD_CTX_free(ctx);
            }
        }

        return (jint)out_len;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

// Decrypts and authenticates AES-GCM-SIV ciphertext (ciphertext || tag).
// Returns: number of plaintext bytes written to outputArray, or -1 on error.
// Throws AEADBadTagException on authentication failure.
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSivSpi_nOpen(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jboolean sameKey,
    jlongArray ctxOut,
    jbyteArray keyArray,
    jbyteArray nonceArray,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jbyteArray outputArray,
    jint outputOffset,
    jbyteArray aadArray,
    jint aadLen)
{
    try {
        raii_env env(pEnv);

        // Create all java_buffers before any borrows
        java_buffer nonceBuf = java_buffer::from_array(env, nonceArray);
        java_buffer inputBuf = java_buffer::from_array(env, inputArray, inputOffset, inputLen);
        java_buffer outputBuf = java_buffer::from_array(env, outputArray, outputOffset);
        java_buffer aadBuf;
        if (aadLen > 0) {
            aadBuf = java_buffer::from_array(env, aadArray, 0, aadLen);
        }

        EVP_AEAD_CTX* ctx;
        bool ownsCtx = false;

        if (ctxPtr != 0 && sameKey == JNI_TRUE) {
            ctx = reinterpret_cast<EVP_AEAD_CTX*>(ctxPtr);
        } else {
            java_buffer keyBuf = java_buffer::from_array(env, keyArray);
            ctx = createAeadCtx(env, keyBuf);
            ownsCtx = true;
        }

        size_t out_len = 0;
        int rv;

        {
            jni_borrow nonce(env, nonceBuf, "nonce");
            jni_borrow input(env, inputBuf, "input");
            jni_borrow output(env, outputBuf, "output");

            if (aadLen > 0) {
                jni_borrow aad(env, aadBuf, "aad");
                rv = EVP_AEAD_CTX_open(ctx,
                    output.data(),
                    &out_len,
                    outputBuf.len(),
                    nonce.data(),
                    GCM_SIV_NONCE_LENGTH,
                    input.data(),
                    inputLen,
                    aad.data(),
                    aadLen);
            } else {
                rv = EVP_AEAD_CTX_open(ctx,
                    output.data(),
                    &out_len,
                    outputBuf.len(),
                    nonce.data(),
                    GCM_SIV_NONCE_LENGTH,
                    input.data(),
                    inputLen,
                    nullptr,
                    0);
            }
        }

        if (unlikely(!rv)) {
            if (ownsCtx) {
                EVP_AEAD_CTX_free(ctx);
            }
            // EVP_AEAD_CTX_open only fails due to authentication failure given validated inputs.
            // Drain any OpenSSL error codes and always signal AEADBadTagException.
            drainOpensslErrors();
            throw java_ex(EX_BADTAG, "Tag mismatch!");
        }

        if (ownsCtx) {
            if (ctxOut != nullptr) {
                jlong tmpPtr = reinterpret_cast<jlong>(ctx);
                pEnv->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
            } else {
                EVP_AEAD_CTX_free(ctx);
            }
        }

        return (jint)out_len;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
