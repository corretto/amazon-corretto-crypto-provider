// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT void Java_com_amazon_corretto_crypto_provider_ConcatenationKdfSpi_nSskdfDigest(JNIEnv* env,
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
        if (SSKDF_digest(output.get(), outputLen, digest, secret.get(), secretLen, info.get(), infoLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "SSKDF_digest failed.");
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_ConcatenationKdfSpi_nSskdfHmac(JNIEnv* env,
    jclass,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jInfo,
    jint infoLen,
    jbyteArray jSalt,
    jint saltLen,
    jbyteArray jOutput,
    jint outputLen)
{
    try {
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);
        JBinaryBlob secret(env, nullptr, jSecret);
        JBinaryBlob info(env, nullptr, jInfo);
        JBinaryBlob salt(env, nullptr, jSalt);
        JBinaryBlob output(env, nullptr, jOutput);
        if (SSKDF_hmac(
                output.get(), outputLen, digest, secret.get(), secretLen, info.get(), infoLen, salt.get(), saltLen)
            != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "SSKDF_hmac failed.");
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}