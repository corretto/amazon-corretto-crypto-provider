// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cassert>
#include <algorithm> // for std::min
#include <openssl/evp.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "buffer.h"
#include "keyutils.h"

#define NATIVE_MODE_ENCRYPT 1
#define NATIVE_MODE_DECRYPT 0

#define EX_BADTAG "javax/crypto/AEADBadTagException"
#define EX_SHORTBUF "javax/crypto/ShortBufferException"

// Number of bytes to process each time we lock the input/output byte arrays
#define CHUNK_SIZE (256 * 1024)

#define MAX_KEY_SIZE 32

#define KEY_LEN_AES128 16
#define KEY_LEN_AES192 24
#define KEY_LEN_AES256 32

using namespace AmazonCorrettoCryptoProvider;

static void initContext(
  raii_env &env,
  raii_cipher_ctx &ctx,
  jint opMode,
  java_buffer key,
  java_buffer iv
) {
    const EVP_CIPHER *cipher;

    switch (key.len()) {
        case KEY_LEN_AES128: cipher = EVP_aes_128_gcm(); break;
        case KEY_LEN_AES192: cipher = EVP_aes_192_gcm(); break;
        case KEY_LEN_AES256: cipher = EVP_aes_256_gcm(); break;
        default: throw java_ex(EX_RUNTIME_CRYPTO, "Unsupported key length");
    }

    // We use a SecureBuffer on the stack rather than a borrow to minimize the number
    // of times we need to cross the JNI boundary (we only need to cross once this way)
    SecureBuffer<uint8_t, KEY_LEN_AES256> keybuf;
    key.get_bytes(env, keybuf.buf, 0, key.len());

    if (unlikely(!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, opMode))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Initializing cipher failed");
    }

    if (unlikely(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.len(), NULL))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Setting IV length failed");
    }

    jni_borrow ivBorrow(env, iv, "iv");

    if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, keybuf, ivBorrow.data(), opMode))) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Final cipher init failed");
    }
}

static int updateLoop(raii_env &env, java_buffer out, java_buffer in, EVP_CIPHER_CTX *ctx) {
    int total_output = 0;

    if (out.len() < in.len()) {
        throw java_ex(EX_ARRAYOOB, "Tried to process more data than would fit in the output buffer");
    }

    while (in.len() > 0) {
        jni_borrow outBorrow(env, out, "output");
        jni_borrow inBorrow(env, in, "input");
        size_t to_process = std::min((size_t)CHUNK_SIZE, in.len());

        int outl;
        int rv = EVP_CipherUpdate(ctx, outBorrow, &outl, inBorrow, to_process);

        if (unlikely(!rv)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "CipherUpdate failed");
        }

        // The java-side checks should prevent us from hitting this assert by
        // enforcing space for an extra buffered ciphertext block minus one
        // byte - unfortunately the EVP interface doesn't give us a straight
        // answer as to how much space we need ahead of time.
        if (unlikely((unsigned int)outl > outBorrow.len())) {
            env.fatal_error("Buffer overrun in cipher loop");
        }

        total_output += outl;
        out = out.subrange(outl);
        in = in.subrange(to_process);
    }

    return total_output;
}

static int cryptFinish(raii_env &env, int opMode, java_buffer resultBuf, unsigned int tagLen, raii_cipher_ctx &ctx) {
    if (opMode == NATIVE_MODE_ENCRYPT &&
        unlikely(tagLen > resultBuf.len())) {
        throw java_ex(EX_SHORTBUF, "No space for GCM tag");
    }

    jni_borrow result(env, resultBuf, "result");

    int outl;
    int rv = EVP_CipherFinal_ex(ctx, result, &outl);

    if (unlikely(!rv)) {
        if (opMode == NATIVE_MODE_DECRYPT) {
            unsigned long errCode = drainOpensslErrors();
            if (likely(errCode == 0)) {
                throw java_ex(EX_BADTAG, "Tag mismatch!");
            } else {
                throw java_ex(EX_RUNTIME_CRYPTO, formatOpensslError(errCode, "CipherFinal failed"));
            }
        }
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "CipherFinal failed");
    }

    // Recheck now that we know how long the potential final block is.
    if (opMode == NATIVE_MODE_ENCRYPT &&
        unlikely(tagLen + outl > resultBuf.len())) {
        throw java_ex(EX_SHORTBUF, "No space for GCM tag");
    }

    if (opMode == NATIVE_MODE_ENCRYPT) {
        // Encrypt: Fetch tag
        int tagRV = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, result.check_range(outl, tagLen));
        if (unlikely(!tagRV)) {
            throw java_ex(EX_RUNTIME_CRYPTO, "Failed to get GCM tag");
        }
        outl += tagLen;
    }

    return outl;
}

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_oneShotEncrypt(
  JNIEnv *pEnv,
  jclass,
  jlong ctxPtr,
  jlongArray ctxOut,
  jbyteArray inputArray,
  jint inoffset,
  jint inlen,
  jbyteArray resultArray,
  jint resultOffset,
  jint tagLen,
  jbyteArray keyArray,
  jbyteArray ivArray
)
{
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        raii_cipher_ctx ctx;
        if (ctxPtr) {
            ctx.borrow(reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr));

            jni_borrow ivBorrow(env, iv, "iv");
            if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_ENCRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
            }
        } else {
            ctx.init();
            EVP_CIPHER_CTX_init(ctx);
            java_buffer key = java_buffer::from_array(env, keyArray);
            initContext(env, ctx, NATIVE_MODE_ENCRYPT, key, iv);
        }

        int outoffset = updateLoop(env, result, input, ctx);
        if (outoffset < 0) return 0;

        result = result.subrange(outoffset);
        int finalOffset = cryptFinish(env, NATIVE_MODE_ENCRYPT, result, tagLen, ctx);

        if (!ctxPtr && ctxOut) {
            // Context is new, but caller does want it back
            jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }

        return finalOffset + outoffset;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptInit__J_3B
  (JNIEnv *pEnv, jclass, jlong ctxPtr, jbyteArray ivArray)
{
    try {
        raii_env env(pEnv);

        if (!ctxPtr) throw java_ex(EX_NPE, "Null context");

        EVP_CIPHER_CTX *ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        jni_borrow ivBorrow(env, iv, "iv");
        if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_ENCRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptInit___3B_3B
  (JNIEnv *pEnv, jclass, jbyteArray keyArray, jbyteArray ivArray)
{
    raii_cipher_ctx ctx;
    ctx.init();
    EVP_CIPHER_CTX_init(ctx);

    try {
        raii_env env(pEnv);

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        initContext(env, ctx, NATIVE_MODE_ENCRYPT, key, iv);

        return (jlong)ctx.take();
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);

        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_releaseContext
  (JNIEnv *, jclass, jlong ctxPtr) {
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)ctxPtr;

    EVP_CIPHER_CTX_free(ctx);
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptUpdate
  (JNIEnv *pEnv,
   jclass,
   jlong ctxPtr,
   jbyteArray inputArray,
   jint inoffset,
   jint inlen,
   jbyteArray resultArray,
   jint resultOffset
) {
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);

        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)ctxPtr;
        return updateLoop(env, result, input, ctx);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

namespace {
void updateAAD_loop(raii_env &env, EVP_CIPHER_CTX *ctx, java_buffer aadData) {
    jni_borrow aad(env, aadData, "aad");

    int outl_ignored;
    // Usually AAD is fairly small, so let's not worry about dropping locks periodically
    if (!EVP_CipherUpdate(ctx, NULL, &outl_ignored, aad, aad.len())) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to update AAD state");
    }
}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptUpdateAAD
  (JNIEnv *pEnv,
   jclass,
   jlong ctxPtr,
   jbyteArray input,
   jint offset,
   jint length
) {
    try {
        raii_env env(pEnv);
        if (!ctxPtr) throw java_ex(EX_NPE, "Null context");

        EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)ctxPtr;
        java_buffer aadBuf = java_buffer::from_array(env, input, offset, length);

        updateAAD_loop(env, ctx, aadBuf);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptDoFinal
  (JNIEnv *pEnv,
   jclass,
   jlong ctxPtr,
   jboolean releaseContext,
   jbyteArray inputArray,
   jint inoffset,
   jint inlength,
   jbyteArray resultArray,
   jint resultOffset,
   jint tagLen
) {
    raii_cipher_ctx ctx;
    if (releaseContext) {
        ctx.move((EVP_CIPHER_CTX *)ctxPtr);
    } else {
        ctx.borrow((EVP_CIPHER_CTX *)ctxPtr);
    }

    int rv = -1;
    try {
        if (!ctx) {
            throw java_ex(EX_NPE, "Null context passed");
        }

        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlength);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);

        int outoffset = updateLoop(env, result, input, ctx);
        result = result.subrange(outoffset);
        int finalOffset = cryptFinish(env, NATIVE_MODE_ENCRYPT, result, tagLen, ctx);

        rv = outoffset + finalOffset;
    } catch (java_ex &ex) {
        EVP_CIPHER_CTX_free(ctx.take());

        ex.throw_to_java(pEnv);
        return -1;
    }

    return rv;
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_oneShotDecrypt(
    JNIEnv *pEnv,
    jclass,
    jlong ctxPtr,
    jlongArray ctxOut,
    jbyteArray inputArray,
    jint inoffset,
    jint inlen,
    jbyteArray resultArray,
    jint resultOffset,
    jint tagLen,
    jbyteArray keyArray,
    jbyteArray ivArray,
    jbyteArray aadBuffer,
    jint aadSize
) {
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        raii_cipher_ctx ctx;
        if (ctxPtr) {
            ctx.borrow(reinterpret_cast<EVP_CIPHER_CTX *>(ctxPtr));

            jni_borrow ivBorrow(env, iv, "iv");
            if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_DECRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
            }
        } else {
            ctx.init();
            EVP_CIPHER_CTX_init(ctx);
            java_buffer key = java_buffer::from_array(env, keyArray);
            initContext(env, ctx, NATIVE_MODE_DECRYPT, key, iv);
        }

        // Decrypt mode: Set the tag before we decrypt
        if (unlikely(tagLen > 16 || tagLen < 0)) {
            throw java_ex(EX_ILLEGAL_ARGUMENT, "Bad tag length");
        }

        if (unlikely(inlen < tagLen)) {
            throw java_ex(EX_BADTAG, "Input too short - need tag");
        }

        SecureBuffer<uint8_t, 16> tag;
        input.get_bytes(env, tag.buf, input.len() - tagLen, tagLen);

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, tag.buf)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set GCM tag");
        }
        input = input.subrange(0, input.len() - tagLen);

        if (aadSize != 0) {
            updateAAD_loop(env, ctx, java_buffer::from_array(env, aadBuffer, 0, aadSize));
        }

        int outoffset = updateLoop(env, result, input, ctx);
        outoffset += cryptFinish(env, NATIVE_MODE_DECRYPT, result.subrange(outoffset), tagLen, ctx);

        if (!ctxPtr && ctxOut) {
            // Context is new, but caller does want it back
            jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
            env->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
        }

        return outoffset;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
