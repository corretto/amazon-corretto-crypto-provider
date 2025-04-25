// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cstring>

#define AES_CFB_BLOCK_SIZE_IN_BYTES 16
#define KEY_LEN_AES128              16
#define KEY_LEN_AES256              32

namespace AmazonCorrettoCryptoProvider {

static bool is_encryption_mode(jint op_mode)
{
    return op_mode == com_amazon_corretto_crypto_provider_AesCfbSpi_ENC_MODE;
}

class AesCfbCipher {
    JNIEnv* jenv_;
    EVP_CIPHER_CTX* ctx_;
    bool own_ctx_;

    static bool output_clobbers_input(uint8_t const* input, int input_len, uint8_t const* output)
    {
        // If the output starts after the input ends, then we're not clobbering anything.
        if ((input + input_len) <= output) {
            return false;
        }

        // If the output starts before the input, we're not clobbering anything.
        if (output + input_len <= input) {
            return false;
        }

        return true;
    }

public:
    AesCfbCipher(JNIEnv* jenv, jlongArray ctx_container, jlong ctx_ptr, bool save_ctx)
        : jenv_(jenv)
        , ctx_(reinterpret_cast<EVP_CIPHER_CTX*>(ctx_ptr))
        , own_ctx_(!save_ctx)
    {
        if (ctx_ != nullptr) {
            // if there is a context, we don't need to do anything.
            return;
        }

        // There is no context, so we need to create one.
        ctx_ = EVP_CIPHER_CTX_new();
        if (ctx_ == nullptr) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CIPHER_CTX_new failed.");
        }

        if (own_ctx_) {
            // Since we should own the context, there is no need to return the context to the caller.
            return;
        }

        // We need to return the context.
        if (ctx_container == nullptr) {
            // This should not happen. We ensure this at the call sites.
            EVP_CIPHER_CTX_free(ctx_);
            throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. No container is provided to return the context.");
        }

        jlong tmpPtr = reinterpret_cast<jlong>(ctx_);
        jenv_->SetLongArrayRegion(ctx_container, 0, 1, &tmpPtr);
    }

    ~AesCfbCipher()
    {
        if (own_ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }

    void init(int op_mode, uint8_t const* key, int key_len, uint8_t const* iv)
    {
        EVP_CIPHER const* cipher;
        switch (key_len) {
        case KEY_LEN_AES128:
            cipher = EVP_aes_128_cfb128();
            break;
        case KEY_LEN_AES256:
            cipher = EVP_aes_256_cfb128();
            break;
        default:
            // This should not happen since we check this in the Java layer.
            throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. Invalid AES key size.");
        }

        if (EVP_CipherInit_ex(ctx_, cipher, nullptr, key, iv, op_mode) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherInit_ex failed.");
        }
    }

    int update(uint8_t const* input, int input_len, uint8_t* output)
    {
        int result = 0;
        if (output_clobbers_input(input, input_len, output)) {
            SimpleBuffer temp(input_len);

            if (EVP_CipherUpdate(ctx_, temp.get_buffer(), &result, input, input_len) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherUpdate failed.");
            }

            std::memcpy(output, temp.get_buffer(), result);
        } else {
            if (EVP_CipherUpdate(ctx_, output, &result, input, input_len) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherUpdate failed.");
            }
        }

        return result;
    }

    int do_final(uint8_t* output)
    {
        int result = 0;
        if (EVP_CipherFinal_ex(ctx_, output, &result) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherFinal_ex failed.");
        }
        return result;
    }
};

}

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCfbSpi_nInitUpdateFinal(JNIEnv* env,
    jclass,
    jint opMode,
    jbyteArray key,
    jint keyLen,
    jbyteArray iv,
    jlongArray ctxContainer,
    jlong ctxPtr,
    jboolean saveCtx,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCfbCipher aes_cfb_cipher(env, ctxContainer, ctxPtr, saveCtx);

        // init
        {
            JBinaryBlob j_key(env, nullptr, key);
            JBinaryBlob j_iv(env, nullptr, iv);
            aes_cfb_cipher.init(opMode, j_key.get(), keyLen, j_iv.get());
        }

        // update and final
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        int result = aes_cfb_cipher.update(io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset);
        result += aes_cfb_cipher.do_final(io_blobs.get_output() + outputOffset + result);

        return result;

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCfbSpi_nInitUpdate(JNIEnv* env,
    jclass,
    jint opMode,
    jbyteArray key,
    jint keyLen,
    jbyteArray iv,
    jlongArray ctxContainer,
    jlong ctxPtr,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCfbCipher aes_cfb_cipher(env, ctxContainer, ctxPtr, true);
        
        // init
        {
            JBinaryBlob j_key(env, nullptr, key);
            JBinaryBlob j_iv(env, nullptr, iv);
            aes_cfb_cipher.init(opMode, j_key.get(), keyLen, j_iv.get());
        }

        // update
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        return aes_cfb_cipher.update(io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCfbSpi_nUpdate(JNIEnv* env,
    jclass,
    jint opMode,
    jlong ctxPtr,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCfbCipher aes_cfb_cipher(env, nullptr, ctxPtr, true);

        // update
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        return aes_cfb_cipher.update(io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCfbSpi_nUpdateFinal(JNIEnv* env,
    jclass,
    jint opMode,
    jlong ctxPtr,
    jboolean saveCtx,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCfbCipher aes_cfb_cipher(env, nullptr, ctxPtr, saveCtx);

        // update and final
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        int result = aes_cfb_cipher.update(io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset);
        result += aes_cfb_cipher.do_final(io_blobs.get_output() + outputOffset + result);

        return result;

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}