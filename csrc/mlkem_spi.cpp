// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "../aws-lc/crypto/fipsmodule/ml_kem/ml_kem.h"
#include "auto_free.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

#define MLKEM_SHARED_SECRET_LEN 32 // Shared secret produced by ML-KEM is always 32 bytes regardless of parameter set

static EVP_PKEY_CTX_auto setupMlKemContext(JNIEnv* pEnv, jlong evpKeyPtr)
{
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
    EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
    CHECK_OPENSSL(ctx.isInitialized());
    return ctx;
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
