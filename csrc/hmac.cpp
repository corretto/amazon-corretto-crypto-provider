// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/hmac.h>
#include "env.h"
#include "util.h"
#include "buffer.h"

#define DO_NOT_INIT -1

using namespace AmazonCorrettoCryptoProvider;

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
        java_buffer ctxBuf = java_buffer::from_array(env, ctxArr);
        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);

        if (evpMd != DO_NOT_INIT) {
            if (keyArr) {
                java_buffer keyBuf = java_buffer::from_array(env, keyArr);
                jni_borrow ctx(env, ctxBuf, "context");
                jni_borrow key(env, keyBuf, "key");
                if (unlikely(HMAC_Init_ex(
                                 reinterpret_cast<HMAC_CTX *>(ctx.data()),
                                 key.data(), key.len(),
                                 reinterpret_cast<const EVP_MD *>(evpMd),
                                 nullptr) != 1))
                {
                    throw_openssl("Unable to initialize HMAC_CTX");
                }
            } else {
                jni_borrow ctx(env, ctxBuf, "context");
                if (unlikely(HMAC_Init_ex(
                                 reinterpret_cast<HMAC_CTX *>(ctx.data()),
                                 nullptr, 0,
                                 nullptr,
                                 nullptr) != 1))
                {
                    throw_openssl("Unable to initialize HMAC_CTX");
                }
            }
        }
        jni_borrow ctx(env, ctxBuf, "context");
        jni_borrow input(env, inputBuf, "input");
        if (unlikely(HMAC_Update(
                         reinterpret_cast<HMAC_CTX *>(ctx.data()),
                         input.data(),
                         input.len()) != 1))
        {
            throw_openssl("Unable to update HMAC_CTX");
        }
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
        java_buffer ctxBuf = java_buffer::from_array(env, ctxArr);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);
        jni_borrow ctx(env, ctxBuf, "context");
        jni_borrow result(env, resultBuf, "result");
        if (unlikely(HMAC_Final(
                         reinterpret_cast<HMAC_CTX *>(ctx.data()),
                         result.data(),
                         nullptr) != 1))
        {
            throw_openssl("Unable to update HMAC_CTX");
        }
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
    Java_com_amazon_corretto_crypto_provider_EvpHmac_updateCtxArray(
        pEnv,
        clazz,
        ctxArr,
        keyArr,
        evpMd,
        inputArr,
        offset,
        len);
    if (unlikely(pEnv->ExceptionCheck())) {
        return;
    }
    Java_com_amazon_corretto_crypto_provider_EvpHmac_doFinal(
        pEnv,
        clazz,
        ctxArr,
        resultArr
    );
}

#ifdef __cplusplus
}
#endif
