// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "util.h"
#include <openssl/hmac.h>

#define DO_NOT_INIT  -1
#define DO_NOT_REKEY -2

// Detect the support of precomputed keys using the fact that HMAC_SHA256_PRECOMPUTED_KEY_SIZE is only defined
// when precomputed keys are supported
#ifdef HMAC_SHA256_PRECOMPUTED_KEY_SIZE
#define HMAC_PRECOMPUTED_KEY_SUPPORT 1
#endif

using namespace AmazonCorrettoCryptoProvider;

// Some of the logic around how to manage arrays is non-standard because HMAC is extremely performance sensitive.
// For the smaller data-sizes we're using, avoiding GetPrimitiveArrayCritical is worth it.

namespace {
void maybe_init_ctx(raii_env& env, HMAC_CTX* ctx, jbyteArray& keyArr, jlong evpMd, jboolean usePrecomputedKey)
{
    if (DO_NOT_INIT == evpMd) {
        return;
    }
    if (DO_NOT_REKEY == evpMd) {
        if (unlikely(HMAC_Init_ex(ctx,
                         nullptr, // key
                         0, // keyLen
                         nullptr, // EVP_MD
                         nullptr /* ENGINE */)
                != 1)) {
            throw_openssl("Unable to initialize HMAC_CTX");
        }
    } else {
        // We pass in keyArr as a jbyteArray to avoid even the minimimal JNI costs
        // of wrapping it in a java_buffer when we don't need it.
        java_buffer keyBuf = java_buffer::from_array(env, keyArr);
        jni_borrow key(env, keyBuf, "key");
        if (unlikely(usePrecomputedKey)) {
#ifdef HMAC_PRECOMPUTED_KEY_SUPPORT
            if (unlikely(
                    HMAC_Init_from_precomputed_key(ctx, key.data(), key.len(), reinterpret_cast<const EVP_MD*>(evpMd))
                    != 1)) {
                throw_openssl("Unable to initialize HMAC_CTX using precomputed key");
            }
#else
            throw_java_ex(EX_ERROR, "Precomputed keys are not supported on this platform/build");
#endif
        } else {
            if (unlikely(HMAC_Init_ex(
                             ctx, key.data(), key.len(), reinterpret_cast<const EVP_MD*>(evpMd), nullptr /* ENGINE */)
                    != 1)) {
                throw_openssl("Unable to initialize HMAC_CTX");
            }
        }
    }
}
}

void update_ctx(raii_env& env, HMAC_CTX* ctx, jni_borrow& input)
{
    if (unlikely(HMAC_Update(ctx, input.data(), input.len()) != 1)) {
        throw_openssl("Unable to update HMAC_CTX");
    }
}

void calculate_mac(raii_env& env, HMAC_CTX* ctx, java_buffer& result)
{
    uint8_t scratch[EVP_MAX_MD_SIZE];
    unsigned int macSize = EVP_MAX_MD_SIZE;
    if (unlikely(HMAC_Final(ctx, scratch, &macSize) != 1)) {
        throw_openssl("Unable to update HMAC_CTX");
    }
    // When we don't need to read the data in an array but use it strictly for output
    // it can be faster to use put_bytes rather than convert it into a jni_borrow.
    result.put_bytes(env, scratch, 0, macSize);
}

jint get_precomputed_key_size(raii_env& env, jstring digestName)
{
#ifdef HMAC_PRECOMPUTED_KEY_SUPPORT
    jni_string name(env, digestName);
    if (!strcmp("md5", name)) {
        return HMAC_MD5_PRECOMPUTED_KEY_SIZE;
    } else if (!strcmp("sha1", name)) {
        return HMAC_SHA1_PRECOMPUTED_KEY_SIZE;
    } else if (!strcmp("sha256", name)) {
        return HMAC_SHA256_PRECOMPUTED_KEY_SIZE;
    } else if (!strcmp("sha384", name)) {
        return HMAC_SHA384_PRECOMPUTED_KEY_SIZE;
    } else if (!strcmp("sha512", name)) {
        return HMAC_SHA512_PRECOMPUTED_KEY_SIZE;
    } else {
        // This should not happen: this function should only be called with valid digest names by the Java code
        throw_java_ex(
            EX_ERROR, "THIS SHOULD NOT BE REACHABLE. Invalid digest name provided to get_precomputed_key_size.");
    }
#else
    throw_java_ex(EX_ERROR, "Precomputed keys are not supported on this platform/build");
#endif
    return 0; // just to please the static verifier, since throw_java_ex always throws an exception
}

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    getContextSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_getContextSize(JNIEnv*, jclass)
{
    return sizeof(HMAC_CTX);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    updateCtxArray
 * Signature: ([B[BJ[BIIZ)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_updateCtxArray(JNIEnv* pEnv,
    jclass,
    jbyteArray ctxArr,
    jbyteArray keyArr,
    jlong evpMd,
    jbyteArray inputArr,
    jint offset,
    jint len,
    jboolean usePrecomputedKey)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);

        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);

        maybe_init_ctx(env, ctx, keyArr, evpMd, usePrecomputedKey);

        jni_borrow input(env, inputBuf, "input");
        update_ctx(env, ctx, input);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    doFinal
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_doFinal(
    JNIEnv* pEnv, jclass, jbyteArray ctxArr, jbyteArray resultArr)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        calculate_mac(env, ctx, resultBuf);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    fastHmac
 * Signature: ([B[BJ[BII[BZ)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_fastHmac(JNIEnv* pEnv,
    jclass,
    jbyteArray ctxArr,
    jbyteArray keyArr,
    jlong evpMd,
    jbyteArray inputArr,
    jint offset,
    jint len,
    jbyteArray resultArr,
    jboolean usePrecomputedKey)
{
    // We do not depend on the other methods because it results in more use to JNI than we want and lower performance
    try {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);
        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        maybe_init_ctx(env, ctx, keyArr, evpMd, usePrecomputedKey);

        {
            jni_borrow input(env, inputBuf, "input");
            update_ctx(env, ctx, input);
        }
        {
            calculate_mac(env, ctx, resultBuf);
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     Java_com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    getPrecomputedKeyLength
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_getPrecomputedKeyLength(
    JNIEnv* pEnv, jclass, jstring digestName)
{
    try {
        raii_env env(pEnv);
        return get_precomputed_key_size(env, digestName);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_HmacWithPrecomputedKeyKeyFactorySpi
 * Method:    getPrecomputedKey
 * Signature: ([BI[BIJ)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HmacWithPrecomputedKeyKeyFactorySpi_getPrecomputedKey(
    JNIEnv* pEnv, jclass, jbyteArray jOutput, jint outputLen, jbyteArray jKey, jint keyLen, jlong evpMd)
{
    try {
#ifdef HMAC_PRECOMPUTED_KEY_SUPPORT
        JBinaryBlob result(pEnv, nullptr, jOutput);
        JBinaryBlob key(pEnv, nullptr, jKey);

        bssl::ScopedHMAC_CTX ctx;

        if (unlikely(HMAC_Init_ex(ctx.get(),
                         key.get(), // key
                         keyLen, // keyLen
                         reinterpret_cast<const EVP_MD*>(evpMd), // EVP_MD
                         nullptr /* ENGINE */)
                != 1)) {
            throw_openssl("Unable to initialize HMAC_CTX");
        }

        if (unlikely(HMAC_set_precomputed_key_export(ctx.get()) != 1)) {
            throw_openssl("Unable to call HMAC_set_precomputed_key_export");
        }

        // HMAC_get_precomputed_key takes as input the length of the buffer
        // and update it to the actual length of the precomputed key.
        // The Java caller always selects the right buffer size, so we should not have any error.
        // But we do a sanity check that this is the case.
        size_t actualOutputLen = outputLen;
        if (unlikely(HMAC_get_precomputed_key(ctx.get(), result.get(), &actualOutputLen) != 1)) {
            throw_openssl("Unable to call HMAC_get_precomputed_key");
        }
        if (unlikely(outputLen < 0 || (size_t)outputLen != actualOutputLen)) {
            throw_java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. invalid output precomputed key length.");
        }
#else
        throw_java_ex(EX_ERROR, "Precomputed keys are not supported on this platform/build");
#endif
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

#ifdef __cplusplus
}
#endif
