// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT void JNICALL
Java_com_amazon_corretto_crypto_provider_Pbkdf2SecretKeyFactorySpi_pbkdf2(JNIEnv* env,
                                                                          jclass,
                                                                          jbyteArray jPassword,
                                                                          jint passwordLen,
                                                                          jbyteArray jSalt,
                                                                          jint saltLen,
                                                                          jint iterations,
                                                                          jint digestCode,
                                                                          jbyteArray jOutput,
                                                                          jint outputLen)
{
    try {
        JByteArrayCritical password(env, jPassword);
        JByteArrayCritical salt(env, jSalt);
        JByteArrayCritical output(env, jOutput);
        EVP_MD const* digest = digest_code_to_EVP_MD(digestCode);

        if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.get()), passwordLen, salt.get(), saltLen,
                              iterations, digest, outputLen, output.get())
            != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "PBKDF2 failed.");
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}
