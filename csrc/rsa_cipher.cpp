// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "generated-headers.h"
#include "util.h"
#include "auto_free.h"
#include "bn.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

void setPaddingParams(EVP_PKEY_CTX *keyCtx, int padding, long oaepMdPtr, long mgfMdPtr)
{
    CHECK_OPENSSL(EVP_PKEY_CTX_set_rsa_padding(keyCtx, padding));
    switch (padding) {
    case RSA_PKCS1_OAEP_PADDING:
        if (oaepMdPtr) {
            CHECK_OPENSSL(EVP_PKEY_CTX_set_rsa_oaep_md(keyCtx, reinterpret_cast<const EVP_MD*>(oaepMdPtr)));
        }
        // intentionally fall-through to set MGF1 digest if specified
    case RSA_PKCS1_PSS_PADDING:
        if (mgfMdPtr) {
            CHECK_OPENSSL(EVP_PKEY_CTX_set_rsa_mgf1_md(keyCtx, reinterpret_cast<const EVP_MD*>(mgfMdPtr)));
        }
        break;
    case RSA_PKCS1_PADDING:
    case RSA_NO_PADDING:
    default:
        break; // nothing to do
    }
    return;
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_RsaCipher_cipher(
    JNIEnv *pEnv,
    jclass,
    jlong ctxHandle,
    jint mode,
    jint padding,
    jlong oaepMdPtr,
    jlong mgfMdPtr,
    jbyteArray input,
    jint inOff,
    jint inLength,
    jbyteArray output,
    jint outOff
)
{

    try {
        raii_env env(pEnv);

        if (!input) {
            throw_java_ex(EX_NPE, "Null input array");
        }
        if (!output) {
            throw_java_ex(EX_NPE, "Null output array");
        }

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(ctxHandle);
        // It is unclear if allocating a new EVP_PKEY_CTX for each operation is expensive.
        // If profiling shows that this is a significant cost when in a hot-path we should figure out a way to
        // cache and reusing the EVP_PKEY_CTX within the context of a single instance of a RsaCipher object.
        // We'll need to be careful to free/replace it when the key changes and properly duplicate it if we
        // decide to implement Cloneable.
        EVP_PKEY_CTX_auto keyCtx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(key, /*engine*/ nullptr));
        CHECK_OPENSSL(keyCtx.isInitialized());

        java_buffer inBuf = java_buffer::from_array(env, input, inOff, inLength);
        java_buffer outBuf = java_buffer::from_array(env, output, outOff, EVP_PKEY_size(key));

        size_t len = outBuf.len();

        {
            jni_borrow in(env, inBuf, "input buffer");
            jni_borrow out(env, outBuf, "output buffer");

            int ret = 0;
            switch (mode) {
            case 2: // Decrypt
            case 4: // Unwrap
                CHECK_OPENSSL(EVP_PKEY_decrypt_init(keyCtx));
                setPaddingParams(keyCtx, padding, oaepMdPtr, mgfMdPtr);
                ret = EVP_PKEY_decrypt(keyCtx, out.data(), &len, in.data(), inLength);
                break;
            case 1: // Encrypt
            case 3: // Wrap
                CHECK_OPENSSL(EVP_PKEY_encrypt_init(keyCtx));
                setPaddingParams(keyCtx, padding, oaepMdPtr, mgfMdPtr);
                ret = EVP_PKEY_encrypt(keyCtx, out.data(), &len, in.data(), inLength);
                break;
            case -1: // Encrypt with a private key, a.k.a. signing
                CHECK_OPENSSL(EVP_PKEY_sign_init(keyCtx));
                setPaddingParams(keyCtx, padding, oaepMdPtr, mgfMdPtr);
                ret = EVP_PKEY_sign(keyCtx, out.data(), &len, in.data(), inLength);
                break;
            case -2: // Decrypt with a public key, a.k.a verification
                CHECK_OPENSSL(EVP_PKEY_verify_recover_init(keyCtx));
                setPaddingParams(keyCtx, padding, oaepMdPtr, mgfMdPtr);
                ret = EVP_PKEY_verify_recover(keyCtx, out.data(), &len, in.data(), inLength);
                break;
            default:
                throw_java_ex(EX_RUNTIME_CRYPTO, "Unknown cipher mode");
            }

            if (ret <= 0) {
                long err = drainOpensslErrors();
                if ((err & RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
                        || (err & RSA_R_PADDING_CHECK_FAILED)
                        || (err & RSA_R_OAEP_DECODING_ERROR)) {
                    throw_java_ex(EX_BADPADDING, formatOpensslError(err, "Bad Padding"));
                } else {
                    throw_openssl(formatOpensslError(err, "Unexpected exception").c_str());
                }
            }
        }

        if (len > outBuf.len()) {   // we've overwritten the buffer, potentially corrupting memory
            abort();
        } else if (len < 0) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected error, negative output length");
        } else if (len & 0xffff0000) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Output length doensn't fit in an int!");
        }

        return (jint) len;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
