// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "env.h"
#include "generated-headers.h"

#include <openssl/evp.h>
#include <openssl/nid.h>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_MlKemGen_generateEvpMlKemKey(
    JNIEnv* pEnv, jclass, jint parameterSet)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL));
        CHECK_OPENSSL(ctx.isInitialized())
        int nid;
        switch (parameterSet) {
        case 512:
            nid = NID_MLKEM512;
            break;
        case 768:
            nid = NID_MLKEM768;
            break;
        case 1024:
            nid = NID_MLKEM1024;
            break;
        default:
            throw java_ex(EX_ILLEGAL_ARGUMENT, "Invalid parameter set");
        }

        CHECK_OPENSSL(EVP_PKEY_CTX_kem_set_params(ctx, nid));
        CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx) == 1);
        CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key.getAddressOfPtr()));
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}
