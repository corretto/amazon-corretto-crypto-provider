// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

typedef int (*EVP_GENERIC_UPDATE_t)(EVP_MD_CTX* ctx, const void* d, size_t cnt);

// Wrapper methods so we can pass pointers to them as EVP_DigestSignUpdate and
// EVP_DigestVerifyUpdate are actually macros so we can't get function pointers
// to them.
int digestSignUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) { return EVP_DigestSignUpdate(ctx, d, cnt); }

int digestVerifyUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) { return EVP_DigestVerifyUpdate(ctx, d, cnt); }

bool configurePadding(raii_env& env, EVP_PKEY_CTX* pctx, int paddingType, const EVP_MD* mgfMd, int pssSaltLen)
{
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

        if (mgfMd != nullptr) {
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

bool initializeContext(raii_env& env,
    EvpKeyContext* ctx,
    bool signMode,
    EVP_PKEY* pKey,
    const EVP_MD* md,
    jint paddingType,
    const EVP_MD* mgfMdPtr,
    jint pssSaltLen)
{
    EVP_PKEY_CTX* pctx; // Logically owned by the ctx so doesn't need to be freed separately

    EVP_PKEY_up_ref(pKey);
    ctx->setKey(pKey);

    if (md != nullptr || EVP_PKEY_id(pKey) == EVP_PKEY_ED25519) {
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

    if (EVP_PKEY_base_id(ctx->getKey()) == EVP_PKEY_RSA) {
        if (!configurePadding(env, pctx, paddingType, mgfMdPtr, pssSaltLen)) {
            throw_openssl("Unable to configure padding");
        }
    }

    return true;
}

void update(raii_env& env, EvpKeyContext* ctx, EVP_GENERIC_UPDATE_t func, java_buffer messageBuf)
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
    JNIEnv* pEnv, EvpKeyContext* ctx, EVP_GENERIC_UPDATE_t func, jbyteArray messageArray, jint offset, jint length)
{
    try {
        raii_env env(pEnv);
        update(env, ctx, func, java_buffer::from_array(env, messageArray, offset, length));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

void bufferUpdate(JNIEnv* pEnv, EvpKeyContext* ctx, EVP_GENERIC_UPDATE_t func, jobject messageDirectBuf)
{
    try {
        raii_env env(pEnv);
        update(env, ctx, func, java_buffer::from_direct(env, messageDirectBuf));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

} // Anonymous namespace

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signStart(JNIEnv* pEnv,
    jclass,
    jlong pKey,
    jlong mdPtr,
    jint paddingType,
    jlong mgfMdPtr,
    jint pssSaltLen,
    jbyteArray message,
    jint offset,
    jint length)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext ctx;

        initializeContext(env, &ctx,
            true, // true->sign
            reinterpret_cast<EVP_PKEY*>(pKey), reinterpret_cast<const EVP_MD*>(mdPtr), paddingType,
            reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);

        update(env, &ctx, digestSignUpdate, java_buffer::from_array(env, message, offset, length));
        return reinterpret_cast<jlong>(ctx.moveToHeap());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signStartBuffer(
    JNIEnv* pEnv, jclass, jlong pKey, jlong mdPtr, jint paddingType, jlong mgfMdPtr, jint pssSaltLen, jobject message)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext ctx;

        initializeContext(env, &ctx,
            true, // true->sign
            reinterpret_cast<EVP_PKEY*>(pKey), reinterpret_cast<const EVP_MD*>(mdPtr), paddingType,
            reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);
        update(env, &ctx, digestSignUpdate, java_buffer::from_direct(env, message));

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStart(JNIEnv* pEnv,
    jclass,
    jlong pKey,
    jlong mdPtr,
    jint paddingType,
    jlong mgfMdPtr,
    jint pssSaltLen,
    jbyteArray message,
    jint offset,
    jint length)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext ctx;

        initializeContext(env, &ctx,
            false, // false->verify
            reinterpret_cast<EVP_PKEY*>(pKey), reinterpret_cast<const EVP_MD*>(mdPtr), paddingType,
            reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);
        update(env, &ctx, digestVerifyUpdate, java_buffer::from_array(env, message, offset, length));

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStartBuffer(
    JNIEnv* pEnv, jclass, jlong pKey, jlong mdPtr, jint paddingType, jlong mgfMdPtr, jint pssSaltLen, jobject message)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext ctx;

        initializeContext(env, &ctx,
            false, // false->verify
            reinterpret_cast<EVP_PKEY*>(pKey), reinterpret_cast<const EVP_MD*>(mdPtr), paddingType,
            reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);
        update(env, &ctx, digestVerifyUpdate, java_buffer::from_direct(env, message));

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signUpdate(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray message, jint offset, jint length)
{
    arrayUpdate(pEnv, reinterpret_cast<EvpKeyContext*>(ctxPtr), digestSignUpdate, message, offset, length);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signUpdateBuffer(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jobject message)
{
    bufferUpdate(pEnv, reinterpret_cast<EvpKeyContext*>(ctxPtr), digestSignUpdate, message);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyUpdate(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray message, jint offset, jint length)
{
    arrayUpdate(pEnv, reinterpret_cast<EvpKeyContext*>(ctxPtr), digestVerifyUpdate, message, offset, length);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyUpdateBuffer(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jobject message)
{
    bufferUpdate(pEnv, reinterpret_cast<EvpKeyContext*>(ctxPtr), digestVerifyUpdate, message);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignature
 * Method:    sign
 * Signature: ([BILjava/lang/String;I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_sign(JNIEnv* pEnv,
    jclass clazz,
    jlong pKey,
    jlong mdPtr,
    jint paddingType,
    jlong mgfMdPtr,
    jint pssSaltLen,
    jbyteArray message,
    jint offset,
    jint length)
{
    jlong ctx = Java_com_amazon_corretto_crypto_provider_EvpSignature_signStart(
        pEnv, clazz, pKey, mdPtr, paddingType, mgfMdPtr, pssSaltLen, message, offset, length);

    if (unlikely(pEnv->ExceptionCheck())) {
        return NULL;
    }

    return Java_com_amazon_corretto_crypto_provider_EvpSignature_signFinish(pEnv, clazz, ctx);
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyFinish(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray signature, jint sigOff, jint sigLen)
{
    EvpKeyContext* ctx = reinterpret_cast<EvpKeyContext*>(ctxPtr);

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

        delete ctx;

        if (likely(result == 1)) {
            return true;
        } else {
            unsigned long errorCode = drainOpensslErrors();

            // Mismatched signatures are not an error case, so return false
            // instead of throwing per JCA convention.
            if (ECDSA_R_MISMATCHED_SIGNATURE == (errorCode & ECDSA_R_MISMATCHED_SIGNATURE)
                || RSA_R_MISMATCHED_SIGNATURE == (errorCode & RSA_R_MISMATCHED_SIGNATURE)) {
                return false;
            }

            // JCA/JCA requires us to try to throw an exception on corrupted signatures, but only if it isn't an RSA
            // signature
            if (errorCode != 0 && keyType != EVP_PKEY_RSA) {
                throw_java_ex(
                    EX_SIGNATURE_EXCEPTION, formatOpensslError(errorCode, "Unknown error verifying signature"));
            }

            return false;
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_signFinish(
    JNIEnv* pEnv, jclass, jlong ctxPtr)
{
    EvpKeyContext* ctx = reinterpret_cast<EvpKeyContext*>(ctxPtr);
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
            // If signature fails due to sizing concerns, give an informative exception
            const uint32_t lastErr = ERR_peek_last_error();
            if ((lastErr & RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE) == RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE
                || (lastErr & RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY) == RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY) {
                drainOpensslErrors();
                throw_java_ex(EX_SIGNATURE_EXCEPTION, formatOpensslError(lastErr, "UNUSED"));
            } else {
                throw_openssl("Unable to sign");
            }
        }

        if (!(signature = env->NewByteArray(sigLength))) {
            throw_java_ex(EX_OOM, "Unable to allocate signature array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(signature, 0, sigLength, (jbyte*)&tmpSig[0]);

        delete ctx;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return signature;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignature
 * Method:    verify
 * Signature: ([BILjava/lang/String;I[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignature_verify(JNIEnv* pEnv,
    jclass clazz,
    jlong pKey,
    jlong mdPtr,
    jint paddingType,
    jlong mgfMdPtr,
    jint pssSaltLen,
    jbyteArray message,
    jint offset,
    jint length,
    jbyteArray signature,
    jint sigOff,
    jint sigLen)
{
    jlong ctx = Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyStart(
        pEnv, clazz, pKey, mdPtr, paddingType, mgfMdPtr, pssSaltLen, message, offset, length);

    if (unlikely(pEnv->ExceptionCheck())) {
        return false;
    }

    return Java_com_amazon_corretto_crypto_provider_EvpSignature_verifyFinish(
        pEnv, clazz, ctx, signature, sigOff, sigLen);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureBase_destroyContext(
    JNIEnv*, jclass, jlong ctxPtr)
{
    delete reinterpret_cast<EvpKeyContext*>(ctxPtr);
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_signRaw(JNIEnv* pEnv,
    jclass clazz,
    jlong pKey,
    jint paddingType,
    jlong mgfMdPtr,
    jint pssSaltLen,
    jbyteArray messageArr,
    jint offset,
    jint length)
{
    try {
        raii_env env(pEnv);
        java_buffer messageBuf = java_buffer::from_array(env, messageArr, offset, length);

        EvpKeyContext ctx;
        initializeContext(env, &ctx,
            true, // true->sign
            reinterpret_cast<EVP_PKEY*>(pKey),
            nullptr, // No message digest
            paddingType, reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);

        std::vector<uint8_t, SecureAlloc<uint8_t> > signature;
        size_t sigLength;

        int keyType = EVP_PKEY_id(reinterpret_cast<EVP_PKEY*>(pKey));

        if (keyType == EVP_PKEY_ED25519) {
            jni_borrow message(env, messageBuf, "message");

            if (!EVP_DigestSign(ctx.getDigestCtx(), NULL, &sigLength, message.data(), message.len())) {
                throw_openssl("Signature failed");
            }

            signature.resize(sigLength);

            if (!EVP_DigestSign(ctx.getDigestCtx(), &signature[0], &sigLength, message.data(), message.len())) {
                throw_openssl("Signature failed");
            }

            signature.resize(sigLength);
        } else {
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
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_verifyRaw(JNIEnv* pEnv,
    jclass clazz,
    jlong pKey,
    jint paddingType,
    jlong mgfMdPtr,
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
        initializeContext(env, &ctx,
            false, // false->verify
            reinterpret_cast<EVP_PKEY*>(pKey),
            nullptr, // no message digest
            paddingType, reinterpret_cast<const EVP_MD*>(mgfMdPtr), pssSaltLen);

        jni_borrow message(env, messageBuf, "message");
        jni_borrow signature(env, signatureBuf, "signature");

        int ret;
        int keyType = EVP_PKEY_id(reinterpret_cast<EVP_PKEY*>(pKey));
        if (keyType == EVP_PKEY_ED25519) {
            ret = EVP_DigestVerify(
                ctx.getDigestCtx(), signature.data(), signature.len(), message.data(), message.len());
        } else {
            ret = EVP_PKEY_verify(ctx.getKeyCtx(), signature.data(), signature.len(), message.data(), message.len());
        }

        if (likely(ret == 1)) {
            return true;
        } else {
            unsigned long errorCode = drainOpensslErrors();

            // Mismatched signatures are not an error case, so return false
            // instead of throwing per JCA convention.
            if (ECDSA_R_MISMATCHED_SIGNATURE == (errorCode & ECDSA_R_MISMATCHED_SIGNATURE)
                || RSA_R_MISMATCHED_SIGNATURE == (errorCode & RSA_R_MISMATCHED_SIGNATURE)
                || EVP_R_INVALID_SIGNATURE == (errorCode & EVP_R_INVALID_SIGNATURE)) {
                return false;
            }

            // JCA/JCA requires us to try to throw an exception on corrupted signatures, but only if it isn't an RSA
            // signature
            if (errorCode != 0 && EVP_PKEY_base_id(ctx.getKey()) != EVP_PKEY_RSA) {
                throw_java_ex(
                    EX_SIGNATURE_EXCEPTION, formatOpensslError(errorCode, "Unknown error verifying signature"));
            }

            return false;
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}
