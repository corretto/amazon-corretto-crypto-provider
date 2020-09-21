// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/dh.h>
#include <openssl/ec.h>
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
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    pkcs82Evp
 * Signature: ([BI)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_pkcs82Evp(
    JNIEnv *pEnv,
    jclass,
    jbyteArray pkcs8der,
    jint nativeValue)
{
    try
    {
        raii_env env(pEnv);
        EvpKeyContext result;

        java_buffer pkcs8Buff = java_buffer::from_array(env, pkcs8der);
        size_t derLen = pkcs8Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, pkcs8Buff, "pkcs8Buff");
            result.setKey(der2EvpPrivateKey(borrow, derLen, false, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result.getKey()) != nativeValue)
            {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.moveToHeap());
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    x5092Evp
 * Signature: ([BI)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_x5092Evp(
    JNIEnv *pEnv,
    jclass,
    jbyteArray x509der,
    jint nativeValue)
{
    try
    {
        raii_env env(pEnv);
        EvpKeyContext result;

        java_buffer x509Buff = java_buffer::from_array(env, x509der);
        size_t derLen = x509Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, x509Buff, "x509Buff");
            result.setKey(der2EvpPublicKey(borrow, derLen, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result.getKey()) != nativeValue)
            {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.moveToHeap());
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    ec2Evp
 * Signature: ([B[B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp(
    JNIEnv *pEnv,
    jclass,
    jbyteArray sArr,
    jbyteArray wxArr,
    jbyteArray wyArr,
    jbyteArray paramsArr)
{
    EC_KEY *ec = NULL;
    try
    {
        raii_env env(pEnv);
        EvpKeyContext ctx;

        {
            // Parse the parameters
            java_buffer paramsBuff = java_buffer::from_array(env, paramsArr);
            size_t paramsLength = paramsBuff.len();
            jni_borrow borrow(env, paramsBuff, "params");

            const unsigned char *derPtr = borrow.data();
            const unsigned char *derMutablePtr = derPtr;

            ec = d2i_ECParameters(NULL, &derMutablePtr, paramsLength);
            if (!ec)
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Invalid parameters");
            }
            if (derPtr + paramsLength != derMutablePtr)
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Extra key information");
            }

            ctx.setKey(EVP_PKEY_new());
            if (!EVP_PKEY_set1_EC_KEY(ctx.getKey(), ec))
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Could not convert to EVP_PKEY");
            }
        }

        // Set the key pieces
        {
            if (sArr)
            {
                BigNumObj s = BigNumObj::fromJavaArray(env, sArr);
                if (EC_KEY_set_private_key(ec, s) != 1)
                {
                    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set private key");
                }
            }

            if (wxArr && wyArr)
            {
                BigNumObj wx = BigNumObj::fromJavaArray(env, wxArr);
                BigNumObj wy = BigNumObj::fromJavaArray(env, wyArr);

                if (EC_KEY_set_public_key_affine_coordinates(ec, wx, wy) != 1)
                {
                    throw_openssl("Unable to set affine coordinates");
                }
            }
        }

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    }
    catch (java_ex &ex)
    {
        EC_KEY_free(ec);
        ex.throw_to_java(pEnv);
        return 0;
    }
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
    unsigned char *der = NULL;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        int keyNid = EVP_PKEY_base_id(ctx->getKey());
        CHECK_OPENSSL(keyNid);

        int derLen = 0;

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
    }
    catch (java_ex &ex)
    {
        OPENSSL_free(der);
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

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_hasCrtParams(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle)
{
    const RSA *r;
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(ctx->getKey()));

        const BIGNUM *dmp1;
        const BIGNUM *dmq1;
        const BIGNUM *iqmp;

        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
        if (!dmp1 || !dmq1 || !iqmp)
        {
            return false;
        }
        if (BN_is_zero(dmp1) || BN_is_zero(dmq1) || BN_is_zero(iqmp))
        {
            return false;
        }
        return true;
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return false;
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

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_dh2Evp(
    JNIEnv *pEnv, jclass, jbyteArray xArr, jbyteArray yArr, jbyteArray paramsDer)
// x = Private, y = Public
{
    DH *dh = NULL;
    EvpKeyContext ctx;
    try
    {
        raii_env env(pEnv);

        {
            // Parse the parameters
            java_buffer paramsBuff = java_buffer::from_array(env, paramsDer);
            size_t paramsLength = paramsBuff.len();
            jni_borrow borrow(env, paramsBuff, "params");

            const unsigned char *derPtr = borrow.data();
            const unsigned char *derMutablePtr = derPtr;

            dh = d2i_DHparams(NULL, &derMutablePtr, paramsLength);
            if (!dh)
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Invalid parameters");
            }
            if (derPtr + paramsLength != derMutablePtr)
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Extra key information");
            }

            ctx.setKey(EVP_PKEY_new());
            if (!EVP_PKEY_set1_DH(ctx.getKey(), dh))
            {
                throw_openssl(EX_INVALID_KEY_SPEC, "Could not convert to EVP_PKEY");
            }
        }

        // Set the key pieces
        {

            BigNumObj x = BigNumObj::fromJavaArray(env, xArr);
            BigNumObj y = BigNumObj::fromJavaArray(env, yArr);

            BIGNUM *xBN = NULL; // Do not FREE!
            BIGNUM *yBN = NULL; // Do not FREE!
            if (xArr)
            {
                xBN = x;
            }
            if (yArr)
            {
                yBN = y;
            }
            if (!DH_set0_key(dh, yBN, xBN))
            {
                throw_openssl(EX_RUNTIME_CRYPTO, "Error setting DH key");
            }
            x.releaseOwnership();
            y.releaseOwnership();
        }

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    }
    catch (java_ex &ex)
    {
        DH_free(dh);
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpDhPublicKey
 * Method:    getY
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpDhPublicKey_getY(
    JNIEnv *pEnv,
    jclass,
    jlong ctxP)
{
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxP);

        DH *dh = EVP_PKEY_get0_DH(ctx->getKey()); // Does not need to be freed
        if (!dh)
        {
            throw_openssl(EX_RUNTIME_CRYPTO, "Could not retrieve DH key");
        }

        const BIGNUM *y = DH_get0_pub_key(dh);
        if (!y)
        {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Could not retrieve Y");
        }

        return bn2jarr(env, y);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpDhPrivateKey
 * Method:    getX
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpDhPrivateKey_getX(
    JNIEnv *pEnv,
    jclass,
    jlong ctxP)
{
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxP);

        DH *dh = EVP_PKEY_get0_DH(ctx->getKey()); // Does not need to be freed
        if (!dh)
        {
            throw_openssl(EX_RUNTIME_CRYPTO, "Could not retrieve DH key");
        }

        const BIGNUM *x = DH_get0_priv_key(dh);
        if (!x)
        {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Could not retrieve X");
        }

        return bn2jarr(env, y);
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpDsaPublicKey
 * Method:    getY
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpDsaPublicKey_getY(
    JNIEnv *pEnv,
    jclass,
    jlong ctxP)
{
    try {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxP);

        DSA *dsa = EVP_PKEY_get0_DSA(ctx->getKey()); // Does not need to be freed
        if (!dsa) {
            throw_openssl(EX_RUNTIME_CRYPTO, "Could not retrieve DH key");
        }

        const BIGNUM *y = DSA_get0_pub_key(dsa);
        if (!y)
        {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Could not retrieve Y");
        }

        return bn2jarr(env, x);
    } catch (java_ex & ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpDsaPrivateKey
 * Method:    getX
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpDsaPrivateKey_getX(
    JNIEnv *pEnv,
    jclass,
    jlong ctxP)
{
    try
    {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxP);

        DSA *dsa = EVP_PKEY_get0_DSA(ctx->getKey()); // Does not need to be freed
        if (!dsa)
        {
            throw_openssl(EX_RUNTIME_CRYPTO, "Could not retrieve DH key");
        }

        const BIGNUM *x = DSA_get0_priv_key(dsa);
        if (!x)
        {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Could not retrieve X");
        }

        return bn2jarr(env, x);
    } catch (java_ex & ex)
    {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}
