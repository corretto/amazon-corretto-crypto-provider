// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT void Java_com_amazon_corretto_crypto_provider_CounterKdfSpi_nKdf(JNIEnv* env,
    jclass,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jInfo,
    jint infoLen,
    jbyteArray jOutput,
    jint outputLen)
{
    try {
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);
        JBinaryBlob secret(env, nullptr, jSecret);
        JBinaryBlob info(env, nullptr, jInfo);
        JBinaryBlob output(env, nullptr, jOutput);
        if (KBKDF_ctr_hmac(output.get(), outputLen, digest, secret.get(), secretLen, info.get(), infoLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "KBKDF_ctr_hmac failed.");
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}
