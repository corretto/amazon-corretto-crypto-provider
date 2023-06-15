// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include <openssl/evp.h>
#include <jni.h>

// Tweak and key are passed in the same buffer. The first 16 bytes
// of this buffer is the tweak and the rest is the key.
static int const AES_XTS_KEY_INDEX_START = 16;

namespace AmazonCorrettoCryptoProvider {

class AesXtsCipher {
public:
    AesXtsCipher(bool for_encryption, unsigned char const* key, unsigned char const* tweak)
    {
        ctx_ = EVP_CIPHER_CTX_new();
        if (ctx_ == nullptr) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CIPHER_CTX_new failed.");
        }

        if (for_encryption) {
            if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_xts(), nullptr, key, tweak) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "EVP_EncryptInit_ex failed.");
            }
        } else {
            if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_xts(), nullptr, key, tweak) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "EVP_DecryptInit_ex failed.");
            }
        }

        // this method always returns 1
        if (EVP_CIPHER_CTX_set_padding(ctx_, 0) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CIPHER_CTX_set_padding");
        }
    }

    ~AesXtsCipher() { EVP_CIPHER_CTX_free(ctx_); }

    void encrypt(unsigned char* input, int input_len, unsigned char* output)
    {
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx_, output, &out_len, input, input_len) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_EncryptUpdate failed.");
        }

        if (EVP_EncryptFinal_ex(ctx_, output + out_len, &out_len) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_EncryptFinal_ex failed.");
        }
    }

    void decrypt(unsigned char* input, int input_len, unsigned char* output)
    {
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx_, output, &out_len, input, input_len) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_DecryptUpdate failed.");
        }

        if (EVP_DecryptFinal_ex(ctx_, output + out_len, &out_len) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_DecryptFinal_ex failed.");
        }
    }

private:
    EVP_CIPHER_CTX* ctx_;
};

}

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_enc(JNIEnv* env,
    jclass,
    jbyteArray jPackedTweakKey,
    jbyteArray jinput,
    jint inputOffset,
    jint inputLen,
    jbyteArray joutput,
    jint outputOffset)
{
    try {
        JByteArrayCritical packedTweakKey(env, jPackedTweakKey);
        JByteArrayCritical input(env, jinput);
        JByteArrayCritical output(env, joutput);

        AesXtsCipher cipher(true, packedTweakKey.get() + AES_XTS_KEY_INDEX_START, packedTweakKey.get());
        cipher.encrypt(input.get() + inputOffset, inputLen, output.get() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_encSameBuffer(JNIEnv* env,
    jclass,
    jbyteArray jPackedTweakKey,
    jbyteArray jinput,
    jint inputOffset,
    jint inputLen,
    jint outputOffset)
{
    try {
        JByteArrayCritical packedTweakKey(env, jPackedTweakKey);
        JByteArrayCritical input(env, jinput);

        AesXtsCipher cipher(true, packedTweakKey.get() + AES_XTS_KEY_INDEX_START, packedTweakKey.get());
        cipher.encrypt(input.get() + inputOffset, inputLen, input.get() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_dec(JNIEnv* env,
    jclass,
    jbyteArray jPackedTweakKey,
    jbyteArray jinput,
    jint inputOffset,
    jint inputLen,
    jbyteArray joutput,
    jint outputOffset)
{
    try {
        JByteArrayCritical packedTweakKey(env, jPackedTweakKey);
        JByteArrayCritical input(env, jinput);
        JByteArrayCritical output(env, joutput);

        AesXtsCipher cipher(false, packedTweakKey.get() + AES_XTS_KEY_INDEX_START, packedTweakKey.get());
        cipher.decrypt(input.get() + inputOffset, inputLen, output.get() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }

    return;
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_decSameBuffer(JNIEnv* env,
    jclass,
    jbyteArray jPackedTweakKey,
    jbyteArray jinput,
    jint inputOffset,
    jint inputLen,
    jint outputOffset)
{
    try {
        JByteArrayCritical packedTweakKey(env, jPackedTweakKey);
        JByteArrayCritical input(env, jinput);

        AesXtsCipher cipher(false, packedTweakKey.get() + AES_XTS_KEY_INDEX_START, packedTweakKey.get());
        cipher.decrypt(input.get() + inputOffset, inputLen, input.get() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}
