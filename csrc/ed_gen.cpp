// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <memory>

using namespace AmazonCorrettoCryptoProvider;

void generateEdEcKey(raii_env* env, EVP_PKEY_auto& key)
{
    EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    CHECK_OPENSSL(ctx.isInitialized());
    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx) > 0);
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key.getAddressOfPtr()));
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EdGen_generateEvpEdEcKey(JNIEnv* pEnv, jclass)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        generateEdEcKey(&env, key);
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}