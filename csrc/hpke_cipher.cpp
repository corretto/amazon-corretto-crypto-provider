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
 * Class:     com_amazon_corretto_crypto_provider_HpkeCipher
 * Method:    hpkeWrap
 * Signature: (J[BIIII[BI)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_hpkeCipher(JNIEnv* pEnv,
    jclass,
    jlong keyHandle,
    jint javaCipherMode,
    jint kemId,
    jint kdfId,
    jint aeadId,
    jbyteArray input,
    jint inputOffset,
    jint inputLen,
    jbyteArray output,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        if (!input) {
            throw_java_ex(EX_NPE, "Empty input array");
        }
        if (!output) {
            throw_java_ex(EX_NPE, "Empty output array");
        }

        const EVP_HPKE_KEY* key = reinterpret_cast<EVP_HPKE_KEY*>(keyHandle);
        const auto kem = EVP_HPKE_KEM_find_by_id(kemId);
        const auto kdf = EVP_HPKE_KDF_find_by_id(kdfId);
        const auto aead = EVP_HPKE_AEAD_find_by_id(aeadId);
        const auto aead_overhead = EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(aead));

        if (kemId != EVP_HPKE_KEM_id(EVP_HPKE_KEY_kem(key))) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "KEM in the key does not match the param");
        }

        // FIXME: support setting these values
        std::vector<uint8_t> info(0);
        std::vector<uint8_t> ad(0);

        size_t result = -1;

        if (javaCipherMode == 3 /* Wrap */) {
            // Serialize public key
            std::vector<uint8_t> public_key_r(EVP_HPKE_KEM_public_key_len(kem));
            size_t public_key_r_len;
            CHECK_OPENSSL(EVP_HPKE_KEY_public_key(key, public_key_r.data(), &public_key_r_len, public_key_r.size()));

            // The input is the plaintext message
            java_buffer msgBuf = java_buffer::from_array(env, input, inputOffset, inputLen);

            // We write the enc and the ciphertext to the output buffer
            const auto encBufLen = EVP_HPKE_KEM_enc_len(kem);
            const auto ctBufLen = inputLen + aead_overhead;
            const auto outBufLen = encBufLen + ctBufLen;
            java_buffer encBuf = java_buffer::from_array(env, output, outputOffset, encBufLen);
            java_buffer ctBuf = java_buffer::from_array(env, output, outputOffset + encBufLen, ctBufLen);
            size_t enc_len = 0;
            size_t ct_len = 0;

            {
                jni_borrow msg(env, msgBuf, "input msg");
                jni_borrow enc(env, encBuf, "output enc");
                jni_borrow ct(env, ctBuf, "output ciphertext");

                CHECK_OPENSSL(EVP_HPKE_seal(enc.data(), &enc_len, enc.size(), ct.data(), &ct_len, ct.size(), kem, kdf,
                    aead, public_key_r.data(), public_key_r_len, info.data(), info.size(), msg.data(), msg.size(),
                    ad.data(), ad.size()));
                if (enc_len != encBufLen) {
                    throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected error, enc buffer length is wrong!");
                }
                if (ct_len != ctBufLen) {
                    throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected error, ciphertext buffer length is wrong!");
                }
                result = outBufLen;
            }
        } else if (javaCipherMode == 4 /* Unwrap */) {
            // The input the enc and the ciphertext
            const auto encBufLen = EVP_HPKE_KEM_enc_len(kem);
            if (inputLen < (encBufLen + aead_overhead)) {
                throw_java_ex(EX_RUNTIME_CRYPTO, "input too short to unwrap with HPKE");
            }
            const auto ctBufLen = inputLen - encBufLen;
            java_buffer encBuf = java_buffer::from_array(env, input, inputOffset, encBufLen);
            java_buffer ctBuf = java_buffer::from_array(env, input, inputOffset + encBufLen, ctBufLen);

            // We write the plaintext message to the output buffer
            java_buffer msgBuf = java_buffer::from_array(env, output, outputOffset);
            size_t msg_len = 0;
            {
                jni_borrow msg(env, msgBuf, "output msg");
                jni_borrow enc(env, encBuf, "input enc");
                jni_borrow ct(env, ctBuf, "input ciphertext");

                CHECK_OPENSSL(EVP_HPKE_open(msg.data(), &msg_len, msg.size(), key, kdf, aead, enc.data(), enc.size(),
                    info.data(), info.size(), ct.data(), ct.size(), ad.data(), ad.size()))
                result = msg_len;
            }
        } else {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported cipher mode");
        }
        return (jint)result;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_HpkeCipher
 * Method:    hpkeOutputSize
 * Signature: (IIIII)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_hpkeOutputSize(
    JNIEnv* pEnv, jclass, jint javaCipherMode, jint kemId, jint kdfId, jint aeadId, jint inputLen)
{
    const auto kem = EVP_HPKE_KEM_find_by_id(kemId);
    const auto aead = EVP_HPKE_AEAD_find_by_id(aeadId);
    const auto aead_overhead = EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(aead));
    const auto enc_len = EVP_HPKE_KEM_enc_len(kem);

    try {
        raii_env env(pEnv);

        if (javaCipherMode == 3 /* Wrap */) {
            // We write the enc and the ciphertext to the output buffer
            return (inputLen + enc_len + aead_overhead);
        } else if (javaCipherMode == 4 /* Unwrap */) {
            // We write the plaintext to the output buffer
            if (inputLen < (enc_len + aead_overhead)) {
                throw_java_ex(EX_RUNTIME_CRYPTO, "input too short to unwrap with HPKE");
            }
            return (inputLen - enc_len - aead_overhead);
        } else {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported cipher mode");
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
