// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/hmac.h>
#include "env.h"
#include "util.h"
#include "buffer.h"

#define DO_NOT_INIT -1
#define DO_NOT_REKEY -2

using namespace AmazonCorrettoCryptoProvider;

// Some of the logic around how to manage arrays is non-standard because HMAC is extremely performance sensitive.
// For the smaller data-sizes we're using, avoiding GetPrimitiveArrayCritical is worth it.

namespace {
    void maybe_init_ctx(raii_env &env, HMAC_CTX *ctx, jbyteArray &keyArr, jlong evpMd) {
        if (DO_NOT_INIT == evpMd) {
            return;
        }
        if (evpMd == DO_NOT_REKEY)
        {
            if (unlikely(HMAC_Init_ex(
                                ctx,
                                nullptr, // key
                                0, // keyLen
                                nullptr, // EVP_MD
                                nullptr /* ENGINE */) != 1))
            {
                throw_openssl("Unable to initialize HMAC_CTX");
            }
        }
        else
        {
            // We pass in keyArr as a jbyteArray to avoid even the minimimal JNI costs
            // of wrapping it in a java_buffer when we don't need it.
            java_buffer keyBuf = java_buffer::from_array(env, keyArr);
            jni_borrow key(env, keyBuf, "key");
            if (unlikely(HMAC_Init_ex(
                             ctx,
                             key.data(),
                             key.len(),
                             reinterpret_cast<const EVP_MD *>(evpMd),
                             nullptr /* ENGINE */) != 1))
            {
                throw_openssl("Unable to initialize HMAC_CTX");
            }
        }
    }

    void update_ctx(raii_env &env, HMAC_CTX *ctx, jni_borrow &input) {
        if (unlikely(HMAC_Update(
                         ctx,
                         input.data(),
                         input.len()) != 1))
        {
            throw_openssl("Unable to update HMAC_CTX");
        }
    }

    void calculate_mac(raii_env &env, HMAC_CTX *ctx, java_buffer &result) {
        uint8_t scratch[EVP_MAX_MD_SIZE];
        unsigned int macSize =EVP_MAX_MD_SIZE;
        if (unlikely(HMAC_Final(
                         ctx,
                         scratch,
                         &macSize) != 1))
        {
            throw_openssl("Unable to update HMAC_CTX");
        }
        // When we don't need to read the data in an array but use it strictly for output
        // it can be faster to use put_bytes rather than convert it into a jni_borrow.
        result.put_bytes(env, scratch, 0, macSize);
    }
}

#ifdef __cplusplus
extern "C"
{
#endif
/*
* Class:     com_amazon_corretto_crypto_provider_EvpHmac
* Method:    getContextSize
* Signature: ()I
*/
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_getContextSize(JNIEnv *, jclass)
{
    return sizeof(HMAC_CTX);
}

/*
* Class:     com_amazon_corretto_crypto_provider_EvpHmac
* Method:    updateCtxArray
* Signature: ([B[BJ[BII)V
*/
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_updateCtxArray(
 JNIEnv *pEnv,
 jclass,
 jbyteArray ctxArr,
 jbyteArray keyArr,
 jlong evpMd,
 jbyteArray inputArr,
 jint offset,
 jint len)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);

        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);

        maybe_init_ctx(env, ctx, keyArr, evpMd);

        jni_borrow input(env, inputBuf, "input");
        update_ctx(env, ctx, input);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
* Class:     com_amazon_corretto_crypto_provider_EvpHmac
* Method:    doFinal
* Signature: ([B[B)V
*/
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_doFinal(
 JNIEnv *pEnv,
 jclass,
 jbyteArray ctxArr,
 jbyteArray resultArr)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        calculate_mac(env, ctx, resultBuf);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}


/*
* Class:     com_amazon_corretto_crypto_provider_EvpHmac
* Method:    fastHmac
* Signature: ([B[BJ[BII[B)V
*/
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_fastHmac(
 JNIEnv *pEnv,
 jclass clazz,
 jbyteArray ctxArr,
 jbyteArray keyArr,
 jlong evpMd,
 jbyteArray inputArr,
 jint offset,
 jint len,
 jbyteArray resultArr)
{
    // We do not depend on the other methods because it results in more use to JNI than we want and lower performance
    try
    {
        raii_env env(pEnv);
        bounce_buffer<HMAC_CTX> ctx = bounce_buffer<HMAC_CTX>::from_array(env, ctxArr);
        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        maybe_init_ctx(env, ctx, keyArr, evpMd);

        {
            jni_borrow input(env, inputBuf, "input");
            update_ctx(env, ctx, input);
        }
        {
            calculate_mac(env, ctx, resultBuf);
        }

    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
}

#ifdef __cplusplus
}
#endif
