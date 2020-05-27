// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "env.h"
#include "buffer.h"
#include "bn.h"
#include "util.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    releaseKey
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_releaseKey(
    JNIEnv *,
    jclass,
    jlong ctxHandle)
{
    delete reinterpret_cast<EvpKeyContext *>(ctxHandle);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePublicKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePublicKey(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    jbyteArray result = NULL;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        unsigned char *der = NULL;
        // This next line allocates memory
        int derLen = i2d_PUBKEY(ctx->getKey(), &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen)))
        {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, (jbyte *)&der[0]);
        OPENSSL_free(der);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePrivateKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePrivateKey(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    jbyteArray result = NULL;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        // This next line allocates memory
        PKCS8_PRIV_KEY_INFO *pkcs8 = EVP_PKEY2PKCS8(ctx->getKey());
        CHECK_OPENSSL(pkcs8);

        unsigned char *der = NULL;
        // This next line allocates memory
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen)))
        {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, (jbyte *)&der[0]);
        OPENSSL_free(der);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    getDerEncodedParams
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_getDerEncodedParams(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    jbyteArray result = NULL;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        int keyNid = EVP_PKEY_base_id(ctx->getKey());
        CHECK_OPENSSL(keyNid);

        int derLen = 0;
        unsigned char *der = NULL;

        switch (keyNid)
        {
        case EVP_PKEY_EC:
            derLen = i2d_ECParameters(EVP_PKEY_get0_EC_KEY(ctx->getKey()), &der);
            break;
        case EVP_PKEY_DH:
            derLen = i2d_DHparams(EVP_PKEY_get0_DH(ctx->getKey()), &der);
            break;
        case EVP_PKEY_DSA:
            derLen = i2d_DSAparams(EVP_PKEY_get0_DSA(ctx->getKey()), &der);
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported key type for parameters");
        }

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen)))
        {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, (jbyte *)der);
        OPENSSL_free(der); // TODO: Fix memory leak
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPublicKey
 * Method:    getPublicPointCoords
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPublicKey_getPublicPointCoords(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle,
    jbyteArray xArr,
    jbyteArray yArr)
{
    const EC_KEY *ecKey = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pubKey = NULL;
    BigNumObj xBN = bn_zero();
    BigNumObj yBN = bn_zero();

    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(ctx->getKey()));
        CHECK_OPENSSL(pubKey = EC_KEY_get0_public_key(ecKey));
        CHECK_OPENSSL(group = EC_KEY_get0_group(ecKey));

        CHECK_OPENSSL(EC_POINT_get_affine_coordinates(group, pubKey, xBN, yBN, NULL) == 1);

        bn2jarr(env, xArr, xBN);
        bn2jarr(env, yArr, yBN);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPrivateKey
 * Method:    getPrivateValue
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPrivateKey_getPrivateValue(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    const EC_KEY *ecKey = NULL;
    const BIGNUM *sBN = NULL;

    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(ctx->getKey()));
        CHECK_OPENSSL(sBN = EC_KEY_get0_private_key(ecKey));

        return bn2jarr(env, sBN);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getModulus(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    const RSA *rsaKey;
    const BIGNUM *n;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(ctx->getKey()));
        CHECK_OPENSSL(n = RSA_get0_n(rsaKey));

        return bn2jarr(env, n);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getPublicExponent(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    const RSA *rsaKey;
    const BIGNUM *e;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(ctx->getKey()));
        CHECK_OPENSSL(e = RSA_get0_e(rsaKey));

        return bn2jarr(env, e);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_getPrivateExponent(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    const RSA *rsaKey;
    const BIGNUM *d;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(ctx->getKey()));
        CHECK_OPENSSL(d = RSA_get0_d(rsaKey));

        return bn2jarr(env, d);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

// protected static native void getCrtParams(long ptr, byte[] crtCoefArr, byte[] expPArr, byte[] expQArr, byte[] primePArr, byte[] primeQArr, byte[] publicExponentArr, byte[] privateExponentArr);
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_getCrtParams(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle,
    jbyteArray coefOut,
    jbyteArray dmPOut,
    jbyteArray dmQOut,
    jbyteArray primePOut,
    jbyteArray primeQOut,
    jbyteArray pubExpOut,
    jbyteArray privExpOut)
{
    const RSA *r;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(ctx->getKey()));

        const BIGNUM *n;
        const BIGNUM *e;
        const BIGNUM *d;
        const BIGNUM *p;
        const BIGNUM *q;
        const BIGNUM *dmp1;
        const BIGNUM *dmq1;
        const BIGNUM *iqmp;

        RSA_get0_key(r, &n, &e, &d);
        RSA_get0_factors(r, &p, &q);
        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);

        bn2jarr(env, pubExpOut, e);
        bn2jarr(env, privExpOut, d);
        bn2jarr(env, primePOut, p);
        bn2jarr(env, primeQOut, q);
        bn2jarr(env, dmPOut, dmp1);
        bn2jarr(env, dmQOut, dmq1);
        bn2jarr(env, coefOut, iqmp);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
}
