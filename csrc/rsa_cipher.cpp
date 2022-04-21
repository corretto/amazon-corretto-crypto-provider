// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "bn.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_RsaCipher_cipher(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle,
    jint mode,
    jint padding,
    jbyteArray input,
    jint inOff,
    jint inLength,
    jbyteArray output,
    jint outOff
)
{

    try {
        raii_env env(pEnv);

        EvpKeyContext *ctx = reinterpret_cast<EvpKeyContext *>(ctxHandle);

        RSA* r = EVP_PKEY_get0_RSA(ctx->getKey()); // Doesn't need to be freed

        if (!r) {
            throw_java_ex(EX_NPE, "Null RSA key");
        }
        if (!input) {
            throw_java_ex(EX_NPE, "Null input array");
        }
        if (!output) {
            throw_java_ex(EX_NPE, "Null output array");
        }

        java_buffer inBuf = java_buffer::from_array(env, input, inOff, inLength);
        java_buffer outBuf = java_buffer::from_array(env, output, outOff, RSA_size(r));
        int len = 0;

        {
            jni_borrow in(env, inBuf, "input buffer");
            jni_borrow out(env, outBuf, "output buffer");

            switch (mode) {
            case 2: // Decrypt
            case 4: // Unwrap
                len = RSA_private_decrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case 1: // Encrypt
            case 3: // Wrap
                len = RSA_public_encrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case -1: // Encrypt with a private key, a.k.a. signing
                len = RSA_private_encrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case -2: // Decrypt with a public key, a.k.a verification
                len = RSA_public_decrypt(inLength, in.data(), out.data(), r, padding);
                break;
            default:
                throw_java_ex(EX_RUNTIME_CRYPTO, "Unknown cipher mode");
            }

            if (len < 0) {
                throw_openssl(EX_BADPADDING, "Unknown error");
            }
        }

        return len;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

