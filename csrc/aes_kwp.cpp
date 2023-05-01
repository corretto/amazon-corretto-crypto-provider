// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <algorithm> // for std::min
#include <cassert>
#include <cstdio>

#define AES_MAX_KEY_SIZE 32

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapPaddingSpi_wrapKey(JNIEnv* pEnv,
    jclass,
    jbyteArray keyArray,
    jbyteArray inputArray,
    jint inputLength,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer input = java_buffer::from_array(env, inputArray, 0, inputLength);
        java_buffer output = java_buffer::from_array(env, outputArray, outputOffset);

        AES_KEY aes_key;
        SecureBuffer<uint8_t, AES_MAX_KEY_SIZE> keybuf;
        if (key.len() > sizeof(keybuf.buf)) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key too large");
        }
        key.get_bytes(env, keybuf.buf, 0, key.len());
        if (AES_set_encrypt_key(keybuf.buf, key.len() * 8, &aes_key) != 0) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key init failed");
        }

        jni_borrow inbuf(env, input, "input");
        jni_borrow outbuf(env, output, "output");
        size_t outlen;
        if (!AES_wrap_key_padded(&aes_key, outbuf.data(), &outlen, outbuf.len(), inbuf.data(), inbuf.len())) {
            throw_openssl(EX_RUNTIME_CRYPTO, "Error wrapping key");
        }

        return outlen;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT int JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapPaddingSpi_unwrapKey(JNIEnv* pEnv,
    jclass,
    jbyteArray keyArray,
    jbyteArray inputArray,
    jint inputLength,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer input = java_buffer::from_array(env, inputArray, 0, inputLength);
        java_buffer output = java_buffer::from_array(env, outputArray, outputOffset);

        AES_KEY aes_key;
        SecureBuffer<uint8_t, AES_MAX_KEY_SIZE> keybuf;
        if (key.len() > sizeof(keybuf.buf)) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key too large");
        }
        key.get_bytes(env, keybuf.buf, 0, key.len());
        if (AES_set_decrypt_key(keybuf.buf, key.len() * 8, &aes_key) != 0) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key init failed");
        }

        jni_borrow inbuf(env, input, "input");
        jni_borrow outbuf(env, output, "output");
        size_t outlen = 0;
        if (!AES_unwrap_key_padded(&aes_key, outbuf.data(), &outlen, outbuf.len(), inbuf.data(), inbuf.len())) {
            throw_openssl(EX_RUNTIME_CRYPTO, "Error unwrapping key");
        }

        return outlen;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
