// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    releaseKey
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_releaseKey(JNIEnv*, jclass, jlong keyHandle)
{
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(keyHandle));
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePublicKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePublicKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;

        // This next line allocates memory
        int derLen = i2d_PUBKEY(key, &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePrivateKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;

        PKCS8_PRIV_KEY_INFO_auto pkcs8 = PKCS8_PRIV_KEY_INFO_auto::from(EVP_PKEY2PKCS8(key));
        CHECK_OPENSSL(pkcs8.isInitialized());

        // This next line allocates memory
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
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
    JNIEnv* pEnv, jclass, jbyteArray pkcs8der, jint evpType, jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto result;

        java_buffer pkcs8Buff = java_buffer::from_array(env, pkcs8der);
        size_t derLen = pkcs8Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, pkcs8Buff, "pkcs8Buff");
            result.set(der2EvpPrivateKey(borrow, derLen, evpType, shouldCheckPrivate, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result) != evpType) {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.take());
    } catch (java_ex& ex) {
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
    JNIEnv* pEnv, jclass, jbyteArray x509der, jint evpType)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto result;

        java_buffer x509Buff = java_buffer::from_array(env, x509der);
        size_t derLen = x509Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, x509Buff, "x509Buff");
            result.set(der2EvpPublicKey(borrow, derLen, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result) != evpType) {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    ec2Evp
 * Signature: ([B[B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp(JNIEnv* pEnv,
    jclass,
    jbyteArray sArr,
    jbyteArray wxArr,
    jbyteArray wyArr,
    jbyteArray paramsArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        EC_KEY_auto ec;
        BN_CTX_auto bn_ctx;
        EC_POINT_auto point;

        {
            // Parse the parameters
            java_buffer paramsBuff = java_buffer::from_array(env, paramsArr);
            size_t paramsLength = paramsBuff.len();
            jni_borrow borrow(env, paramsBuff, "params");

            const unsigned char* derPtr = borrow.data();
            const unsigned char* derMutablePtr = derPtr;

            ec.set(d2i_ECParameters(NULL, &derMutablePtr, paramsLength));
            if (!ec.isInitialized()) {
                throw_openssl(EX_INVALID_KEY_SPEC, "Invalid parameters");
            }
            if (derPtr + paramsLength != derMutablePtr) {
                throw_openssl(EX_INVALID_KEY_SPEC, "Extra key information");
            }

            key.set(EVP_PKEY_new());
            if (!EVP_PKEY_set1_EC_KEY(key, ec)) {
                throw_openssl(EX_INVALID_KEY_SPEC, "Could not convert to EVP_PKEY");
            }
        }

        // Set the key pieces
        {
            if (sArr) {
                BigNumObj s = BigNumObj::fromJavaArray(env, sArr);
                if (EC_KEY_set_private_key(ec, s) != 1) {
                    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set private key");
                }

                if (!wxArr || !wyArr) {
                    // We have to calculate this ourselves.
                    // Otherwise, it will be taken care of later
                    const EC_GROUP* group = EC_KEY_get0_group(ec);
                    CHECK_OPENSSL(group);
                    CHECK_OPENSSL(point.set(EC_POINT_new(group)));
                    CHECK_OPENSSL(bn_ctx.set(BN_CTX_new()));

                    CHECK_OPENSSL(EC_POINT_mul(group, point, s, NULL, NULL, bn_ctx) == 1);

                    CHECK_OPENSSL(EC_KEY_set_public_key(ec, point) == 1);

                    unsigned int oldFlags = EC_KEY_get_enc_flags(ec);
                    EC_KEY_set_enc_flags(ec, oldFlags | EC_PKEY_NO_PUBKEY);
                }
                if (shouldCheckPrivate && !checkKey(key)) {
                    throw_openssl(EX_INVALID_KEY_SPEC, "Key fails check");
                }
            }

            if (wxArr && wyArr) {
                BigNumObj wx = BigNumObj::fromJavaArray(env, wxArr);
                BigNumObj wy = BigNumObj::fromJavaArray(env, wyArr);

                if (EC_KEY_set_public_key_affine_coordinates(ec, wx, wy) != 1) {
                    throw_openssl("Unable to set affine coordinates");
                }
            }
        }

        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    getDerEncodedParams
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_getDerEncodedParams(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;

        int keyNid = EVP_PKEY_base_id(key);
        CHECK_OPENSSL(keyNid);

        int derLen = 0;

        switch (keyNid) {
        case EVP_PKEY_EC:
            derLen = i2d_ECParameters(EVP_PKEY_get0_EC_KEY(key), &der);
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported key type for parameters");
        }

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPublicKey
 * Method:    getPublicPointCoords
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPublicKey_getPublicPointCoords(
    JNIEnv* pEnv, jclass, jlong keyHandle, jbyteArray xArr, jbyteArray yArr)
{
    const EC_KEY* ecKey = NULL;
    const EC_GROUP* group = NULL;
    const EC_POINT* pubKey = NULL;
    BigNumObj xBN = bn_zero();
    BigNumObj yBN = bn_zero();

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(key));
        CHECK_OPENSSL(pubKey = EC_KEY_get0_public_key(ecKey));
        CHECK_OPENSSL(group = EC_KEY_get0_group(ecKey));

        CHECK_OPENSSL(EC_POINT_get_affine_coordinates(group, pubKey, xBN, yBN, NULL) == 1);

        bn2jarr(env, xArr, xBN);
        bn2jarr(env, yArr, yBN);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPrivateKey
 * Method:    getPrivateValue
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPrivateKey_getPrivateValue(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const EC_KEY* ecKey = NULL;
    const BIGNUM* sBN = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(key));
        CHECK_OPENSSL(sBN = EC_KEY_get0_private_key(ecKey));

        return bn2jarr(env, sBN);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEdPrivateKey
 * Method:    getPrivateKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEdPrivateKey_getPrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        size_t bufSize;

        CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, NULL, &bufSize) == 1);
        SimpleBuffer privateKeyBuffer(bufSize);
        CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, privateKeyBuffer.get_buffer(), &bufSize) == 1);

        result = env->NewByteArray(bufSize);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate private key array");
        }
        env->SetByteArrayRegion(result, 0, bufSize, (jbyte*)privateKeyBuffer.get_buffer());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getModulus(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* n;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(n = RSA_get0_n(rsaKey));

        return bn2jarr(env, n);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getPublicExponent(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* e;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(e = RSA_get0_e(rsaKey));

        return bn2jarr(env, e);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_getPrivateExponent(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* d;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(d = RSA_get0_d(rsaKey));

        return bn2jarr(env, d);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_hasCrtParams(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* r;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(key));

        const BIGNUM* dmp1;
        const BIGNUM* dmq1;
        const BIGNUM* iqmp;

        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
        if (!dmp1 || !dmq1 || !iqmp) {
            return false;
        }
        if (BN_is_zero(dmp1) || BN_is_zero(dmq1) || BN_is_zero(iqmp)) {
            return false;
        }
        return true;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}

// protected static native void getCrtParams(long ptr, byte[] crtCoefArr, byte[] expPArr, byte[] expQArr, byte[]
// primePArr, byte[] primeQArr, byte[] publicExponentArr, byte[] privateExponentArr);
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_getCrtParams(JNIEnv* pEnv,
    jclass,
    jlong keyHandle,
    jbyteArray coefOut,
    jbyteArray dmPOut,
    jbyteArray dmQOut,
    jbyteArray primePOut,
    jbyteArray primeQOut,
    jbyteArray pubExpOut,
    jbyteArray privExpOut)
{
    const RSA* r;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(key));

        const BIGNUM* n;
        const BIGNUM* e;
        const BIGNUM* d;
        const BIGNUM* p;
        const BIGNUM* q;
        const BIGNUM* dmp1;
        const BIGNUM* dmq1;
        const BIGNUM* iqmp;

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
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    rsa2Evp
 * Signature: ([B[B[B[B[B[B[B[B)J
 * modulus, publicExponentArr, privateExponentArr, crtCoefArr, expPArr, expQArr, primePArr, primeQArr
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_rsa2Evp(JNIEnv* pEnv,
    jclass,
    jbyteArray modulusArray,
    jbyteArray publicExponentArr,
    jbyteArray privateExponentArr,
    jbyteArray crtCoefArr,
    jbyteArray expPArr,
    jbyteArray expQArr,
    jbyteArray primePArr,
    jbyteArray primeQArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        RSA_auto rsa;

        if (unlikely(!rsa.set(RSA_new()))) {
            throw_openssl(EX_OOM, "Unable to create RSA object");
        }

        BigNumObj modulus = BigNumObj::fromJavaArray(env, modulusArray);
        // Java allows for weird degenerate keys with the public exponent being NULL.
        // We simulate this with zero.
        BigNumObj pubExp = bn_zero();
        if (publicExponentArr) {
            jarr2bn(env, publicExponentArr, pubExp);
        }

        if (privateExponentArr) {
            BigNumObj privExp = BigNumObj::fromJavaArray(env, privateExponentArr);

            if (BN_is_zero(pubExp)) {
                // RSA blinding can't be performed without |e|.
                rsa.set(new_private_RSA_key_with_no_e(modulus, privExp));
                // new_private_RSA_key_with_no_e does not take the ownership of its arguments
            } else {
                if (RSA_set0_key(rsa, modulus, pubExp, privExp) != 1) {
                    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA values");
                }
                // RSA_set0_key takes ownership
                modulus.releaseOwnership();
                pubExp.releaseOwnership();
                privExp.releaseOwnership();
            }
        } else {
            if (RSA_set0_key(rsa, modulus, pubExp, NULL) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA values");
            }
            // RSA_set0_key takes ownership
            modulus.releaseOwnership();
            pubExp.releaseOwnership();
        }

        if (primePArr && primeQArr) {
            BigNumObj p = BigNumObj::fromJavaArray(env, primePArr);
            BigNumObj q = BigNumObj::fromJavaArray(env, primeQArr);

            if (RSA_set0_factors(rsa, p, q) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA factors");
            }

            // RSA_set0_factors takes ownership
            p.releaseOwnership();
            q.releaseOwnership();
        }

        if (crtCoefArr && expPArr && expQArr) {
            BigNumObj iqmp = BigNumObj::fromJavaArray(env, crtCoefArr);
            BigNumObj dmp1 = BigNumObj::fromJavaArray(env, expPArr);
            BigNumObj dmq1 = BigNumObj::fromJavaArray(env, expQArr);

            if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA CRT values");
            }

            // RSA_set0_crt_params takes ownership
            iqmp.releaseOwnership();
            dmp1.releaseOwnership();
            dmq1.releaseOwnership();
        }

        key.set(EVP_PKEY_new());
        if (!key.isInitialized()) {
            throw_openssl(EX_OOM, "Unable to create EVP key");
        }

        if (unlikely(EVP_PKEY_set1_RSA(key, rsa) != 1)) {
            throw_openssl(EX_OOM, "Unable to assign RSA key");
        }
        // We can only check consistency if the CRT parameters are present
        if (shouldCheckPrivate && !!crtCoefArr && !checkKey(key)) {
            throw_openssl(EX_INVALID_KEY_SPEC, "Key fails check");
        }
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpRsaPrivateKey
 * Method:    encodeRsaPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_encodeRsaPrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;
        PKCS8_PRIV_KEY_INFO_auto pkcs8;

        const RSA* rsaKey = NULL;
        const BIGNUM* e = NULL;
        const BIGNUM* d = NULL;
        const BIGNUM* n = NULL;
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        RSA_get0_key(rsaKey, &n, &e, &d);
        if (BN_null_or_zero(e)) {

            EVP_PKEY_auto stack_key;
            RSA_auto zeroed_rsa;

            // Key is lacking the public exponent so we must encode manually
            // Fortunately, this must be the most boring type of key (no params)
            BIGNUM* zeroedE = BN_dup(e);
            if (nullptr == zeroedE) {
                CHECK_OPENSSL(zeroedE = BN_new());
            }

            CHECK_OPENSSL(zeroed_rsa.set(RSA_new()));
            if (!RSA_set0_key(zeroed_rsa, BN_dup(n), zeroedE, BN_dup(d))) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA components");
            }
            if (!RSA_set0_factors(zeroed_rsa, BN_new(), BN_new())) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA factors");
            }
            if (!RSA_set0_crt_params(zeroed_rsa, BN_new(), BN_new(), BN_new())) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA CRT components");
            }
            stack_key.set(EVP_PKEY_new());
            CHECK_OPENSSL(stack_key.isInitialized());
            EVP_PKEY_set1_RSA(stack_key, zeroed_rsa);

            CHECK_OPENSSL(pkcs8.set(EVP_PKEY2PKCS8(stack_key)));

        } else {
            // This is a normal key and we don't need to do anything special
            CHECK_OPENSSL(pkcs8.set(EVP_PKEY2PKCS8(key)));
        }

        // This next line allocates memory
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}

#if !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)
/*
 * Class:     com_amazon_corretto_crypto_provider_EvpRsaPrivateKey
 * Method:    encodeRsaPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpMlDsaPrivateKey_encodeMlDsaPrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_PQDSA);

        uint8_t* der;
        size_t der_len;
        CBB cbb;
        CHECK_OPENSSL(CBB_init(&cbb, 0));
        // Failure below may just indicate that we don't have the seed, so retry with |encodeExpandedMLDSAPrivateKey|
        // and encode in PKCS8 (RFC 5208) format after clearing the error queue.
        if (EVP_marshal_private_key(&cbb, key)) {
            if (!CBB_finish(&cbb, &der, &der_len)) {
                OPENSSL_free(der);
                throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing seed ML-DSA key");
            }
        } else {
            ERR_clear_error();
            der_len = encodeExpandedMLDSAPrivateKey(key, &der);
        }
        CBB_cleanup(&cbb);

        if (!(result = env->NewByteArray(der_len))) {
            OPENSSL_free(der);
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, der_len, (const jbyte*)der);
        OPENSSL_free(der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}
#endif // !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKemKey
 * Method:    getKeySize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpKemKey_nativeGetKeySize(
    JNIEnv* pEnv, jclass, jlong pkeyPtr)
{
    EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(pkeyPtr);
    if (!pkey) {
        return -1;
    }

    size_t key_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &key_len) == 1) {
        return (jint)key_len;
    }
    return -1;
}
