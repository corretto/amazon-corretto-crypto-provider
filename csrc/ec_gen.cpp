// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <memory>
#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "bn.h"
#include "buffer.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EcGen
 * Method:    buildEcParams
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_buildEcParams
(JNIEnv *pEnv, jclass, jint nid) {
    EVP_PKEY_CTX *paramCtx = nullptr;
    jlong retval;

    try {
        paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

        if (!paramCtx) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to create param context");
        }

        if (!EVP_PKEY_paramgen_init(paramCtx)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize param context");
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(&*paramCtx, nid)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to set curve");
        }

        EVP_PKEY *param = NULL;
        if (!EVP_PKEY_paramgen(paramCtx, &param)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to generate parameters");
        }

        retval = (jlong) param;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        retval = 0;
    }

    EVP_PKEY_CTX_free(paramCtx);
    return retval;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcGen
 * Method:    freeEcParams
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_freeEcParams
(JNIEnv *env, jclass, jlong param) {
    EVP_PKEY_free((EVP_PKEY*) param);
}

// Converts from OpenSSL EC_KEY and EC_GROUP objects to jbyteArrays.
// The return values are stored in pre-allocated jbyteArrays.
// This will throw Java exceptions upon failures
// This does not currently return a success value because it is currently only
// used as the last call in methods where the control flow does not vary
// based on the success of this method.
void opensslEcKey2Jarrs
(raii_env &env,
 const EC_KEY* ecKey,
 const EC_GROUP* group,
 jbyteArray xArr,
 jbyteArray yArr,
 jbyteArray sArr) {

    BigNumObj xBN = bn_zero();
    BigNumObj yBN = bn_zero();

    // const pointers returned by get0 methods do not need to be freed
    const BIGNUM *sBN = NULL;
    const EC_POINT *pubKey = NULL;
    const EC_METHOD *method = NULL;

    // Convert the key into numbers
    CHECK_OPENSSL(pubKey = EC_KEY_get0_public_key(ecKey));

    // Figure out if this is a prime or a binary field, because they use different methods
    method = EC_GROUP_method_of((EC_GROUP*) group);
    switch (EC_METHOD_get_field_type(method)) {
        case NID_X9_62_prime_field:
            CHECK_OPENSSL(EC_POINT_get_affine_coordinates_GFp((EC_GROUP*) group, pubKey, xBN, yBN, NULL) == 1);
            break;
        case NID_X9_62_characteristic_two_field:
            CHECK_OPENSSL(EC_POINT_get_affine_coordinates_GFp((EC_GROUP*) group, pubKey, xBN, yBN, NULL) == 1);
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unknown curve type");
    }

    bn2jarr(env, xArr, xBN);
    bn2jarr(env, yArr, yBN);

    CHECK_OPENSSL(sBN = EC_KEY_get0_private_key(ecKey));

    bn2jarr(env, sArr, sBN);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcGen
 * Method:    generateEcKey
 * Signature: (I[B[B[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEcKey(
  JNIEnv *pEnv,
  jclass,
  jlong param,
  jlong group,
  jboolean checkConsistency,
  jbyteArray xArr,
  jbyteArray yArr,
  jbyteArray sArr)
{
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ecKey = NULL;

    try {
        raii_env env(pEnv);

        // Actually set up the key
        CHECK_OPENSSL(keyCtx = EVP_PKEY_CTX_new((EVP_PKEY*) param, NULL));
        CHECK_OPENSSL(EVP_PKEY_keygen_init(keyCtx) > 0);
        CHECK_OPENSSL(EVP_PKEY_keygen(keyCtx, &pkey));
        CHECK_OPENSSL(ecKey = EVP_PKEY_get1_EC_KEY(pkey));
        if (checkConsistency) {
            CHECK_OPENSSL(EC_KEY_check_key(ecKey) == 1);
        }
        opensslEcKey2Jarrs(env, ecKey, (EC_GROUP*) group, xArr, yArr, sArr);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    // Always clean up after ourselves on the way out
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(keyCtx);
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEcKeyFromSpec(
  JNIEnv *pEnv,
  jclass,
  jbyteArray paramsDer,
  jboolean checkConsistency,
  jbyteArray xArr,
  jbyteArray yArr,
  jbyteArray sArr)
{
    std::vector<uint8_t, SecureAlloc<uint8_t> > derBuf;
    EC_KEY *ecParams = NULL;
    EC_KEY *key = NULL;
    const EC_GROUP* group;

    EvpKeyContext keyCtx, paramCtx;

    try {
        raii_env env(pEnv);

        // First, parse the params
        derBuf = java_buffer::from_array(env, paramsDer).to_vector(env);
        const unsigned char* tmp = (const unsigned char*) &derBuf[0]; // necessary due to modification
        if(!likely(ecParams = d2i_ECParameters(NULL, &tmp, derBuf.size()))) {
            throw_openssl("Unable to parse parameters");
        }

        // Now that we have the params, extract the group from them (all we care about)
        CHECK_OPENSSL(group = EC_KEY_get0_group(ecParams));

        // Setup the temporary PKEY context with the extracted parameters.
        if (!paramCtx.setKeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
            throw_openssl("Unable to create new evp key context");
        }
        CHECK_OPENSSL(EVP_PKEY_paramgen_init(paramCtx.getKeyCtx()) == 1);
        CHECK_OPENSSL(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx.getKeyCtx(), EC_GROUP_get_curve_name(group)) == 1);
        // We need to define a temporary pointer to an EVP_PKEY
        // to be able to call EVP_PKEY_paramgen function.
        EVP_PKEY *tmpKey0 = NULL;
        CHECK_OPENSSL(EVP_PKEY_paramgen(paramCtx.getKeyCtx(), &tmpKey0) == 1);
        paramCtx.setKey(tmpKey0);

        // Generate the actual EC key.
        if (!keyCtx.setKeyCtx(EVP_PKEY_CTX_new(paramCtx.getKey(), NULL))) {
            throw_openssl("Unable to create new evp key context");
        }
        CHECK_OPENSSL(EVP_PKEY_keygen_init(keyCtx.getKeyCtx()) == 1);
        // We need to define a temporary pointer to an EVP_PKEY
        // to be able to call EVP_PKEY_keygen function.
        EVP_PKEY *tmpKey1 = NULL;
        CHECK_OPENSSL(EVP_PKEY_keygen(keyCtx.getKeyCtx(), &tmpKey1) == 1);
        keyCtx.setKey(tmpKey1);
        CHECK_OPENSSL(key = EVP_PKEY_get0_EC_KEY(keyCtx.getKey()));

        if (checkConsistency) {
            CHECK_OPENSSL(EC_KEY_check_key(key) == 1);
        }

        opensslEcKey2Jarrs(env, key, group, xArr, yArr, sArr);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    EC_KEY_free(ecParams);
}

