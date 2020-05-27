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
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_buildEcParams(JNIEnv *pEnv, jclass, jint nid)
{
    EVP_PKEY_CTX *paramCtx = nullptr;
    jlong retval;

    try
    {
        paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

        if (!paramCtx)
        {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to create param context");
        }

        if (!EVP_PKEY_paramgen_init(paramCtx))
        {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize param context");
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(&*paramCtx, nid))
        {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to set curve");
        }

        EVP_PKEY *param = NULL;
        if (!EVP_PKEY_paramgen(paramCtx, &param))
        {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to generate parameters");
        }

        retval = (jlong)param;
    }
    catch (java_ex &ex)
    {
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
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_freeEcParams(JNIEnv *env, jclass, jlong param)
{
    EVP_PKEY_free((EVP_PKEY *)param);
}

void generateEcKey(raii_env *env, EvpKeyContext &ctx, EVP_PKEY *param, jboolean checkConsistency)
{
    ctx.setKeyCtx(EVP_PKEY_CTX_new(param, NULL));
    CHECK_OPENSSL(ctx.getKeyCtx());
    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx.getKeyCtx()) > 0);
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx.getKeyCtx(), ctx.getKeyPtr()));
    if (checkConsistency)
    {
        EC_KEY *ecKey = NULL;
        CHECK_OPENSSL(ecKey = EVP_PKEY_get1_EC_KEY(ctx.getKey()));
        int check_result = EC_KEY_check_key(ecKey);
        EC_KEY_free(ecKey);
        CHECK_OPENSSL(check_result);
    }
    ctx.setKeyCtx(NULL);
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKey(
    JNIEnv *pEnv,
    jclass,
    jlong param,
    jboolean checkConsistency)
{
    try
    {
        raii_env env(pEnv);

        // Actually set up the key
        EvpKeyContext ctx;
        generateEcKey(&env, ctx, reinterpret_cast<EVP_PKEY *>(param), checkConsistency);
        return reinterpret_cast<jlong>(ctx.moveToHeap());
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

JNIEXPORT long JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKeyFromSpec(
    JNIEnv *pEnv,
    jclass,
    jbyteArray paramsDer,
    jboolean checkConsistency)
{
    // TODO, figure out how to do this with EVP
    std::vector<uint8_t, SecureAlloc<uint8_t>> derBuf;
    EC_KEY *ecParams = NULL;
    EVP_PKEY *params_as_pkey = EVP_PKEY_new();
    EvpKeyContext ctx;

    try
    {
        raii_env env(pEnv);

        // First, parse the params

        // Since the ecParams object doesn't seem to need freeing,
        // I am suspicious that it depends on the backing buffer.
        // So, I don't feel comfortable releasing of freeing it before we're
        // completely done
        derBuf = java_buffer::from_array(env, paramsDer).to_vector(env);
        const unsigned char *tmp = (const unsigned char *)&derBuf[0]; // necessary due to modification
        if (!likely(ecParams = d2i_ECParameters(NULL, &tmp, derBuf.size())))
        {
            throw_openssl("Unable to parse parameters");
        }

        CHECK_OPENSSL(EVP_PKEY_assign_EC_KEY(params_as_pkey, ecParams));
        ecParams = NULL; // Ownership taken by previous line

        generateEcKey(&env, ctx, params_as_pkey, checkConsistency);

        return reinterpret_cast<jlong>(ctx.moveToHeap());
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
    }

    EC_KEY_free(ecParams);
    EVP_PKEY_free(params_as_pkey);
    return 0;
}
