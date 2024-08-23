// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/nid.h>

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_HpkeGen
 * Method:    generateEvpHpkeKemKeyFromSpec
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_HpkeGen_generateEvpHpkeKemKeyFromSpec(
    JNIEnv* pEnv, jclass, jint hpke_kem_id)
{
    EVP_HPKE_KEY_auto key;
    try {
        raii_env env(pEnv);
        key.set(EVP_HPKE_KEY_new());
        const EVP_HPKE_KEM* kem = EVP_HPKE_KEM_find_by_id(hpke_kem_id);
        CHECK_OPENSSL(kem != NULL);
        CHECK_OPENSSL(EVP_HPKE_KEY_generate(key, kem));
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}