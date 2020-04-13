// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <vector>
#include "generated-headers.h"
#include "env.h"
#include "buffer.h"
#include "util.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

namespace {

typedef int (*EVP_GENERIC_UPDATE_t) (EVP_MD_CTX *ctx, const void *d, size_t cnt);

// Wrapper methods so we can pass pointers to them as EVP_DigestSignUpdate and
// EVP_DigestVerifyUpdate are actually macros so we can't get function pointers
// to them.
int digestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    return EVP_DigestSignUpdate(ctx, d, cnt);
}

int digestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    return EVP_DigestVerifyUpdate(ctx, d, cnt);
}

const EVP_MD* digestFromJstring(raii_env &env, jstring digestName) {
    if (!digestName) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Null Digest name");
        return NULL;
    }
    jni_string name(env, digestName);
    const EVP_MD* result = EVP_get_digestbyname(name.native_str);

    if (!result) {
        throw_openssl("Unable to get digest");
    }

    return result;
}

bool configurePadding(raii_env &env, EVP_PKEY_CTX* pctx, int paddingType, jstring mgfMdName, int pssSaltLen) {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, paddingType) <= 0) {
        throw_openssl("Unable to set padding");
    }

    switch (paddingType) {
    case RSA_PKCS1_PADDING:
        // No additional configuration needed
        break;
    case RSA_PKCS1_PSS_PADDING:
        // Handle PSS configuration if present
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, pssSaltLen) <= 0) {
            throw_openssl("Unable to set salt len");
        }

        if (mgfMdName) {
            const EVP_MD *mgfMd = digestFromJstring(env, mgfMdName);

            if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgfMd) <= 0) {
                throw_openssl("Unable to set MGF digest");
            }
        }
        break;
    default:
        throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected padding type");
    }

    return true;
}

bool initializeContext
(
 raii_env &env,
 EvpKeyContext* ctx,
 bool signMode,
 jbyteArray derArr,
 jint keyType,
 bool checkPrivateKey,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen
 )
{
    int derLen = 0;
    EVP_PKEY_CTX* pctx; // Logically owned by the ctx so doesn't need to be freed separately

    if (!ctx->getKey()) {
        java_buffer derBuf = java_buffer::from_array(env, derArr);

        jni_borrow der(env, derBuf, "der");

        derLen = derBuf.len();

        if (signMode) {
            ctx->setKey(der2EvpPrivateKey(der.data(), derLen, checkPrivateKey, EX_SIGNATURE_EXCEPTION));
        } else {
            ctx->setKey(der2EvpPublicKey(der.data(), derLen, EX_SIGNATURE_EXCEPTION));
        }
    }

    if (!ctx->getKey()) {
        throw_openssl("Unable to convert key");
    }

    if (EVP_PKEY_base_id(ctx->getKey()) != keyType) {
        throw_java_ex(EX_SIGNATURE_EXCEPTION, "Unexpected key type for algorithm");
    }

    if (digestName) {
        const EVP_MD *md = NULL;
        md = digestFromJstring(env, digestName);

        if (!ctx->setDigestCtx(EVP_MD_CTX_create())) {
            throw_openssl("Unable to create MD_CTX");
        }

        int result;
        if (signMode) {
            result = EVP_DigestSignInit(ctx->getDigestCtx(), &pctx, md, NULL, ctx->getKey());
        } else {
            result = EVP_DigestVerifyInit(ctx->getDigestCtx(), &pctx, md, NULL, ctx->getKey());
        }
        if (result != 1) {
            throw_openssl("Unable to initialize signature");
        }
    } else {
        pctx = ctx->setKeyCtx(EVP_PKEY_CTX_new(ctx->getKey(), NULL));
        if (!pctx) {
            throw_openssl("Unable to create PKEY_CTX");
        }

        int result;
        if (signMode) {
            result = EVP_PKEY_sign_init(ctx->getKeyCtx());
        } else {
            result = EVP_PKEY_verify_init(ctx->getKeyCtx());
        }

        if (result <= 0) {
            throw_openssl("Unable to initialize raw sign/verify context");
        }
    }

    if (keyType == EVP_PKEY_RSA) {
        if (!configurePadding(env, pctx, paddingType, mgfMdName, pssSaltLen)) {
            throw_openssl("Unable to configure padding");
        }
    }

    return true;
}

void update(
 raii_env &env,
 EvpKeyContext* ctx,
 EVP_GENERIC_UPDATE_t func,
 java_buffer messageBuf)
{
    if (!ctx) {
        throw_java_ex(EX_NPE, "Null context");
    }

    if (!ctx->getDigestCtx()) {
        throw_java_ex(EX_ILLEGAL_STATE, "Tried to perform incremental updates on a raw signature context");
    }

    jni_borrow message(env, messageBuf, "message");

    int result = (*func)(ctx->getDigestCtx(), message.data(), message.len());
    if (!result) {
        throw_openssl("Unable to update signature");
    }
}

void arrayUpdate(
 JNIEnv *pEnv,
 EvpKeyContext* ctx,
 EVP_GENERIC_UPDATE_t func,
 jbyteArray messageArray,
 jint offset,
 jint length)
{
    try {
        raii_env env(pEnv);
        update(env, ctx, func, java_buffer::from_array(env, messageArray, offset, length));
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

void bufferUpdate(
 JNIEnv *pEnv,
 EvpKeyContext* ctx,
 EVP_GENERIC_UPDATE_t func,
 jobject messageDirectBuf)
{
    try {
        raii_env env(pEnv);
        update(env, ctx, func, java_buffer::from_direct(env, messageDirectBuf));
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

} // Anonymous namespace

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signStart
(JNIEnv *pEnv,
 jclass,
 jbyteArray derArr,
 jlong ctxHandle,
 jint keyType,
 jboolean checkPrivateKey,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray message,
 jint offset,
 jint length
)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext newCtx;
        EvpKeyContext* ctx = ctxHandle ? (EvpKeyContext*) ctxHandle : &newCtx;

        initializeContext(env, ctx, true, derArr, keyType, checkPrivateKey, digestName, paddingType, mgfMdName, pssSaltLen);
        update(env, ctx, digestSignUpdate, java_buffer::from_array(env, message, offset, length));

        if (ctx == &newCtx) {
            ctx = newCtx.moveToHeap();
        }
        return (jlong) ctx;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signStartBuffer
(JNIEnv *pEnv,
 jclass,
 jbyteArray derArr,
 jlong ctxHandle,
 jint keyType,
 jboolean checkPrivateKey,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jobject message
)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext newCtx;
        EvpKeyContext* ctx = ctxHandle ? (EvpKeyContext*) ctxHandle : &newCtx;

        initializeContext(env, ctx, true, derArr, keyType, checkPrivateKey, digestName, paddingType, mgfMdName, pssSaltLen);
        update(env, ctx, digestSignUpdate, java_buffer::from_direct(env, message));

        if (ctx == &newCtx) {
            ctx = newCtx.moveToHeap();
        }
        return (jlong) ctx;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStart
(JNIEnv *pEnv,
 jclass,
 jbyteArray derArr,
 jlong ctxHandle,
 jint keyType,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray message,
 jint offset,
 jint length
)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext newCtx;
        EvpKeyContext* ctx = ctxHandle ? (EvpKeyContext*) ctxHandle : &newCtx;

        initializeContext(env, ctx, false, derArr, keyType, false, digestName, paddingType, mgfMdName, pssSaltLen);
        update(env, ctx, digestVerifyUpdate, java_buffer::from_array(env, message, offset, length));

        if (ctx == &newCtx) {
            ctx = newCtx.moveToHeap();
        }
        return (jlong) ctx;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStartBuffer
(JNIEnv *pEnv,
 jclass,
 jbyteArray derArr,
 jlong ctxHandle,
 jint keyType,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jobject message
)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext newCtx;
        EvpKeyContext* ctx = ctxHandle ? (EvpKeyContext*) ctxHandle : &newCtx;

        initializeContext(env, ctx, false, derArr, keyType, false, digestName, paddingType, mgfMdName, pssSaltLen);
        update(env, ctx, digestVerifyUpdate, java_buffer::from_direct(env, message));

        if (ctx == &newCtx) {
            ctx = newCtx.moveToHeap();
        }
        return (jlong) ctx;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signUpdate
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jbyteArray message,
 jint offset,
 jint length) {
    arrayUpdate(pEnv, (EvpKeyContext*) ctxPtr, digestSignUpdate, message, offset, length);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signUpdateBuffer
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jobject message
) {
    bufferUpdate(pEnv, (EvpKeyContext*) ctxPtr, digestSignUpdate, message);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyUpdate
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jbyteArray message,
 jint offset,
 jint length) {
    arrayUpdate(pEnv, (EvpKeyContext*) ctxPtr, digestVerifyUpdate, message, offset, length);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyUpdateBuffer
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jobject message
) {
    bufferUpdate(pEnv, (EvpKeyContext*) ctxPtr, digestVerifyUpdate, message);
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignature
 * Method:    sign
 * Signature: ([BILjava/lang/String;I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_sign
(JNIEnv *pEnv,
 jclass clazz,
 jbyteArray derArr,
 jlongArray ctxHandleArr,
 jint keyType,
 jboolean checkPrivateKey,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray message,
 jint offset,
 jint length
)
{
    jlong ctxHandle = 0;
    // Yes, this is outside our standard environment handling
    if (ctxHandleArr != NULL) {
        pEnv->GetLongArrayRegion(ctxHandleArr, 0, 1, &ctxHandle);
        if (pEnv->ExceptionCheck()) {
            return NULL;
        }
    }

    jlong ctx = Java_com_amazon_corretto_crypto_provider_EvpSignature_signStart(
            pEnv,
            clazz,
            derArr,
            ctxHandle,
            keyType,
            checkPrivateKey,
            digestName,
            paddingType,
            mgfMdName,
            pssSaltLen,
            message,
            offset,
            length);

    if (unlikely(pEnv->ExceptionCheck())) {
        return NULL;
    }
    
    jbyteArray result = Java_com_amazon_corretto_crypto_provider_EvpSignature_signFinish(
        pEnv,
        clazz,
        ctx,
        ctxHandleArr != NULL);

    if (ctxHandleArr && ctxHandle == 0) {
        pEnv->SetLongArrayRegion(ctxHandleArr, 0, 1, &ctx);
    }
    return result;
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyFinish
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jbyteArray signature,
 jint sigOff,
 jint sigLen,
 jboolean preserveCtx)
{
    EvpKeyContext* ctx = (EvpKeyContext*) ctxPtr;

    try {
        raii_env env(pEnv);

        if (!ctxPtr) {
            throw_java_ex(EX_NPE, "Null context");
        }

        int keyType = EVP_PKEY_base_id(ctx->getKey());
        // might throw
        java_buffer signatureBuf = java_buffer::from_array(env, signature, sigOff, sigLen);
        jni_borrow sigBorrow(env, signatureBuf, "signature");

        int result = EVP_DigestVerifyFinal(ctx->getDigestCtx(), sigBorrow.data(), sigBorrow.len());

        if (!preserveCtx) {
            delete ctx;
        }

        if (likely(result == 1)) {
            return true;
        } else {
            unsigned long errorCode = drainOpensslErrors();

            // JCA/JCA requires us to try to throw an exception on corrupted signatures, but only if it isn't an RSA signature
            if (errorCode != 0 && keyType != EVP_PKEY_RSA) {
              throw_java_ex(EX_SIGNATURE_EXCEPTION, formatOpensslError(errorCode, "Unknown error verifying signature"));
            }

            return false;
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signFinish
(JNIEnv *pEnv,
 jclass,
 jlong ctxPtr,
 jboolean preserveCtx)
{
    EvpKeyContext* ctx = (EvpKeyContext*) ctxPtr;
    jbyteArray signature = NULL;

    try {
        raii_env env(pEnv);

        if (!ctx) {
            throw_java_ex(EX_NPE, "Null context");
        }

        size_t sigLength = 0;
        std::vector<uint8_t, SecureAlloc<uint8_t> > tmpSig;

        if (!EVP_DigestSignFinal(ctx->getDigestCtx(), NULL, &sigLength)) {
            throw_openssl("Unable to get signature length");
        }

        tmpSig.resize(sigLength);

        if (!EVP_DigestSignFinal(ctx->getDigestCtx(), &tmpSig[0], &sigLength)) {
            throw_openssl("Unable to sign");
        }

        if (!(signature = env->NewByteArray(sigLength))) {
            throw_java_ex(EX_OOM, "Unable to allocate signature array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(signature, 0, sigLength, (jbyte*) &tmpSig[0]);

        if (!preserveCtx) {
            delete ctx;
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    return signature;
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignature
 * Method:    verify
 * Signature: ([BILjava/lang/String;I[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verify
(JNIEnv *pEnv,
 jclass clazz,
 jbyteArray derArr,
 jlongArray ctxHandleArr,
 jint keyType,
 jstring digestName,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray message,
 jint offset,
 jint length,
 jbyteArray signature,
 jint sigOff,
 jint sigLen)
{
    jlong ctxHandle = 0;
    // Yes, this is outside our standard environment handling
    if (ctxHandleArr != NULL) {
        pEnv->GetLongArrayRegion(ctxHandleArr, 0, 1, &ctxHandle);
        if (pEnv->ExceptionCheck()) {
            return 0;
        }
    }
    jlong ctx = Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStart(
            pEnv,
            clazz,
            derArr,
            ctxHandle,
            keyType,
            digestName,
            paddingType,
            mgfMdName,
            pssSaltLen,
            message,
            offset,
            length);

    if (unlikely(pEnv->ExceptionCheck())) {
        return false;
    }
    
    jboolean result = Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyFinish(
        pEnv,
        clazz,
        ctx,
        signature,
        sigOff,
        sigLen,
        ctxHandleArr != NULL);

    if (ctxHandleArr && ctxHandle == 0) {
        pEnv->SetLongArrayRegion(ctxHandleArr, 0, 1, &ctx);
    }
    return result;
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureBase_destroyContext
(JNIEnv *,
 jclass,
 jlong ctxPtr)
{
    delete (EvpKeyContext*) ctxPtr;
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_signRaw
(JNIEnv *pEnv,
 jclass clazz,
 jbyteArray derArr,
 jint keyType,
 jboolean checkPrivateKey,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray messageArr,
 jint offset,
 jint length
)
{
    try {
        raii_env env(pEnv);
        java_buffer messageBuf = java_buffer::from_array(env, messageArr, offset, length);

        EvpKeyContext ctx;
        initializeContext(env, &ctx, true, derArr, keyType, checkPrivateKey, NULL, paddingType, mgfMdName, pssSaltLen);

        std::vector<uint8_t, SecureAlloc<uint8_t> > signature;
        {
            size_t sigLength;
            jni_borrow message(env, messageBuf, "message");

            if (EVP_PKEY_sign(ctx.getKeyCtx(), NULL, &sigLength, message.data(), message.len()) <= 0) {
                throw_openssl("Signature failed");
            }

            signature.resize(sigLength);

            if (EVP_PKEY_sign(ctx.getKeyCtx(), &signature[0], &sigLength, message.data(), message.len()) <= 0) {
                throw_openssl("Signature failed");
            }

            if (signature.size() < sigLength) {
                pEnv->FatalError("Unexpected buffer overflow");
            }

            signature.resize(sigLength);
        }
        
        return vecToArray(env, signature);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_verifyRaw
(JNIEnv *pEnv,
 jclass clazz,
 jbyteArray derArr,
 jint keyType,
 jint paddingType,
 jstring mgfMdName,
 jint pssSaltLen,
 jbyteArray messageArr,
 jint offset,
 jint length,
 jbyteArray signatureArr,
 jint sigOff,
 jint sigLen)
{
    try {
        raii_env env(pEnv);
        java_buffer messageBuf = java_buffer::from_array(env, messageArr, offset, length);
        java_buffer signatureBuf = java_buffer::from_array(env, signatureArr, sigOff, sigLen);

        EvpKeyContext ctx;
        initializeContext(env, &ctx, false, derArr, keyType, false, NULL, paddingType, mgfMdName, pssSaltLen);

        jni_borrow message(env, messageBuf, "message");
        jni_borrow signature(env, signatureBuf, "signature");

        int ret = EVP_PKEY_verify(ctx.getKeyCtx(), signature.data(), signature.len(), message.data(), message.len());

        if (likely(ret == 1)) {
            return true;
        } else {
            unsigned long errorCode = drainOpensslErrors();

            // JCA/JCA requires us to try to throw an exception on corrupted signatures, but only if it isn't an RSA signature
            if (errorCode != 0 && keyType != EVP_PKEY_RSA) {
              throw_java_ex(EX_SIGNATURE_EXCEPTION, formatOpensslError(errorCode, "Unknown error verifying signature"));
            }

            return false;
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}


