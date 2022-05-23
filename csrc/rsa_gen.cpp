// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <cstring> // for memset
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include "bn.h"
#include "auto_free.h"

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_RsaGen_generateEvpKey(
    JNIEnv *pEnv,
    jclass,
    jint bits,
    jboolean checkConsistency,
    jbyteArray pubExp)
{
    RSA_auto r = RSA_auto::from(RSA_new());

    try
    {
        raii_env env(pEnv);

        BigNumObj bne;
        jarr2bn(env, pubExp, bne);

        if (1 != RSA_generate_key_ex(r, bits, bne, NULL))
        {
            throw_openssl("Unable to generate key");
        }

        if (checkConsistency && RSA_check_key(r) != 1)
        {
            throw_openssl("Key failed consistency check");
        }

        EVP_PKEY_auto result = EVP_PKEY_auto::from(EVP_PKEY_new());
        CHECK_OPENSSL(result.isInitialized());
        CHECK_OPENSSL(EVP_PKEY_set1_RSA(result, r));

        return reinterpret_cast<jlong>(result.take());
    }
    catch (java_ex &ex)
    {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
