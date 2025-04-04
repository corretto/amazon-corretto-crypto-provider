// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>
#include <openssl/hkdf.h>

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdf(JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jSalt,
    jint saltLen,
    jbyteArray jInfo,
    jint infoLen)
{
    try {
        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical secret(env, jSecret);
        JByteArrayCritical salt(env, jSalt);
        JByteArrayCritical info(env, jInfo);
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);

        if (HKDF(output.get(), outputLen, digest, secret.get(), secretLen, salt.get(), saltLen, info.get(), infoLen)
            != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF failed.");
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdfExtract(
    JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jSalt,
    jint saltLen)
{
    try {
        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical secret(env, jSecret);
        JByteArrayCritical salt(env, jSalt);
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);

        size_t out_len = 0;
        if (HKDF_extract(output.get(), &out_len, digest, secret.get(), secretLen, salt.get(), saltLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF_extract failed.");
        }
        assert(out_len == EVP_MD_size(digest) && outputLen >= 0 && out_len == (size_t)outputLen);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdfExpand(
    JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jPrk,
    jint prkLen,
    jbyteArray jInfo,
    jint infoLen)
{
    try {
        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical prk(env, jPrk);
        JByteArrayCritical info(env, jInfo);
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);

        if (HKDF_expand(output.get(), outputLen, digest, prk.get(), prkLen, info.get(), infoLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF_expand failed.");
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}
