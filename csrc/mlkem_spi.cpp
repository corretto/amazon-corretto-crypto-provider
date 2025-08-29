// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include "../aws-lc/crypto/fipsmodule/ml_kem/ml_kem.h"

using namespace AmazonCorrettoCryptoProvider;

# define MLKEM_SHARED_SECRET_LEN 32 // Shared secret produced by ML-KEM is always 32 bytes regardless of parameter set

static int ciphertextLengthToParameterSet(size_t ciphertext_len)
{
    switch (ciphertext_len) {
    case MLKEM512_CIPHERTEXT_BYTES:
        return 512;
    case MLKEM768_CIPHERTEXT_BYTES:
        return 768;
    case MLKEM1024_CIPHERTEXT_BYTES:
        return 1024;
    default:
        return -1;
    }
}

static EVP_PKEY_CTX_auto setupMlKemContext(JNIEnv* pEnv, jlong evpKeyPtr) {
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
    EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
    CHECK_OPENSSL(ctx.isInitialized());
    return ctx;
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MlKemSpi_nativeGetParameterSet(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_CTX_auto ctx = setupMlKemContext(pEnv, evpKeyPtr);
        size_t ciphertext_len, shared_secret_len;

        // Pass in NULL to get sizes of ciphertext array and shared secret array for the given key's parameter set
        CHECK_OPENSSL(EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL, &shared_secret_len)); 
        int paramSet = ciphertextLengthToParameterSet(ciphertext_len);
        return paramSet;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MlKemSpi_nativeEncapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr, jbyteArray ciphertextArray, jbyteArray sharedSecretArray)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_CTX_auto ctx = setupMlKemContext(pEnv, evpKeyPtr);

        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);

        size_t ciphertext_len = env->GetArrayLength(ciphertextArray);
        size_t shared_secret_len = MLKEM_SHARED_SECRET_LEN;
        CHECK_OPENSSL(
            EVP_PKEY_encapsulate(ctx, ciphertext.get(), &ciphertext_len, shared_secret.get(), &shared_secret_len));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MlKemSpi_nativeDecapsulate(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr, jbyteArray ciphertextArray, jbyteArray sharedSecretArray)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_CTX_auto ctx = setupMlKemContext(pEnv, evpKeyPtr);

        jsize ciphertext_len = env->GetArrayLength(ciphertextArray);
        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);

        size_t shared_secret_len = MLKEM_SHARED_SECRET_LEN;
        CHECK_OPENSSL(
                EVP_PKEY_decapsulate(ctx, shared_secret.get(), &shared_secret_len, ciphertext.get(), ciphertext_len));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}
