// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

static void generateKey(EVP_PKEY_auto& key, int keyId)
{
    EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new_id(keyId, nullptr));
    CHECK_OPENSSL(ctx.isInitialized());
    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx) == 1);
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key.getAddressOfPtr()) == 1);
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyPairGenerator_generateEvpKey(
    JNIEnv* pEnv, jclass, jint nativeKeyId)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        generateKey(key, nativeKeyId);
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}