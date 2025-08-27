// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

// ML-KEM constants
#define MLKEM_SHARED_SECRET_SIZE   32
#define MLKEM_512_CIPHERTEXT_SIZE  768
#define MLKEM_768_CIPHERTEXT_SIZE  1088
#define MLKEM_1024_CIPHERTEXT_SIZE 1568

static int ciphertextLengthToParameterSet(size_t ciphertext_len)
{
    switch (ciphertext_len) {
    case MLKEM_512_CIPHERTEXT_SIZE:
        return 512;
    case MLKEM_768_CIPHERTEXT_SIZE:
        return 768;
    case MLKEM_1024_CIPHERTEXT_SIZE:
        return 1024;
    default:
        return -1;
    }
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_KemUtils_nativeGetParameterSet(
    JNIEnv* pEnv, jclass, jlong evpKeyPtr)
{
    try {
        raii_env env(pEnv);
        if (unlikely(!evpKeyPtr)) {
            throw_java_ex(EX_NPE, "Null key pointer");
        }

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (!ctx.isInitialized()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }

        size_t ciphertext_len, shared_secret_len;
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

        if (unlikely(!evpKeyPtr)) {
            throw_java_ex(EX_NPE, "Null key pointer");
        }

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (unlikely(!ctx.isInitialized())) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }

        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);

        size_t ciphertext_len = env->GetArrayLength(ciphertextArray);
        size_t shared_secret_len = MLKEM_SHARED_SECRET_SIZE;

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

        if (unlikely(!evpKeyPtr)) {
            throw_java_ex(EX_NPE, "Null key pointer");
        }

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(evpKeyPtr);
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, NULL));
        if (unlikely(!ctx.isInitialized())) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Failed to create EVP context");
        }

        jsize ciphertext_array_len = env->GetArrayLength(ciphertextArray);
        JBinaryBlob ciphertext(pEnv, nullptr, ciphertextArray);
        JBinaryBlob shared_secret(pEnv, nullptr, sharedSecretArray);

        size_t shared_secret_len = MLKEM_SHARED_SECRET_SIZE;
        CHECK_OPENSSL(
            EVP_PKEY_decapsulate(ctx, shared_secret.get(), &shared_secret_len, ciphertext.get(), ciphertext_array_len));

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}
