// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cstring>
#include <jni.h>

#define AES_CBC_BLOCK_SIZE_IN_BYTES 16
#define KEY_LEN_AES128              16
#define KEY_LEN_AES192              24
#define KEY_LEN_AES256              32

namespace AmazonCorrettoCryptoProvider {

class AesCbcCipher {
    JNIEnv* jenv_;
    EVP_CIPHER_CTX* ctx_;
    bool own_ctx_;

    static bool output_clobbers_input(uint8_t const* input, int input_len, uint8_t const* output, int unprocessed_input)
    {
        // Let's say we have 5 unprocessed bytes. The first 11 (16 - 5) bytes of input would produce 16 bytes of output.
        // To avoid overwriting the input, output must be at least 11 bytes behind input.
        int delta = (unprocessed_input == 0) || (unprocessed_input == AES_CBC_BLOCK_SIZE_IN_BYTES)
            ? unprocessed_input
            : (AES_CBC_BLOCK_SIZE_IN_BYTES - unprocessed_input);
        if ((output + delta) <= input) {
            return false;
        }

        // If the output starts after the input ends, then we're not clobbering anything.
        if ((input + input_len) <= output) {
            return false;
        }

        return true;
    }

    static void check_unprocessed_input(int unprocessed_input)
    {
        if (unprocessed_input < 0 || unprocessed_input > 16) {
            // This should not be reachable since we check this in Java.
            throw java_ex(EX_ERROR, "unprocessed_input is not in [0, 16] range.");
        }
    }

public:
    AesCbcCipher(JNIEnv* jenv, jlongArray ctx_container, jlong ctx_ptr, bool save_ctx)
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

    ~AesCbcCipher()
    {
        if (own_ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }

    void init(int op_mode, int padding, uint8_t const* key, int key_len, uint8_t const* iv)
    {
        EVP_CIPHER const* cipher;
        switch (key_len) {
        case KEY_LEN_AES128:
            cipher = EVP_aes_128_cbc();
            break;
        case KEY_LEN_AES192:
            cipher = EVP_aes_192_cbc();
            break;
        case KEY_LEN_AES256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            // This should not happen since we check this in the Java layer.
            throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. Invalid AES key size.");
        }

        if (EVP_CipherInit_ex(ctx_, cipher, nullptr, key, iv, op_mode) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherInit_ex failed.");
        }

        // This method always returns 1 and succeeds.
        if (EVP_CIPHER_CTX_set_padding(ctx_, padding) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CIPHER_CTX_set_padding failed.");
        }
    }

    int update(uint8_t const* input, int input_len, uint8_t* output, int unprocessed_input)
    {
        check_unprocessed_input(unprocessed_input);
        int result = 0;
        if (output_clobbers_input(input, input_len, output, unprocessed_input)) {
            SimpleBuffer temp(input_len + unprocessed_input);

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
            if (ERR_GET_REASON(ERR_get_error()) == CIPHER_R_BAD_DECRYPT) {
                throw java_ex(EX_BADPADDING, "Bad padding");
            } else {
                throw_openssl(EX_RUNTIME_CRYPTO, "EVP_CipherFinal_ex failed.");
            }
        }
        return result;
    }
};

}

using namespace AmazonCorrettoCryptoProvider;

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nInitUpdateFinal(JNIEnv* env,
    jclass,
    jint opMode,
    jint padding,
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
        AesCbcCipher aes_cbc_cipher(env, ctxContainer, ctxPtr, saveCtx);
        // init
        {
            JBinaryBlob j_key(env, nullptr, key);
            JBinaryBlob j_iv(env, nullptr, iv);
            aes_cbc_cipher.init(opMode, padding, j_key.get(), keyLen, j_iv.get());
        }

        int result = 0;

        // update
        JBinaryBlob output(env, outputDirect, outputArray);

        {
            JBinaryBlob input(env, inputDirect, inputArray);
            result = aes_cbc_cipher.update(input.get() + inputOffset, inputLen, output.get() + outputOffset, 0);
        }

        // final
        result += aes_cbc_cipher.do_final(output.get() + outputOffset + result);

        return result;
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nInitUpdate(JNIEnv* env,
    jclass,
    jint opMode,
    jint padding,
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
        AesCbcCipher aes_cbc_cipher(env, ctxContainer, ctxPtr, true);
        // init
        {
            JBinaryBlob j_key(env, nullptr, key);
            JBinaryBlob j_iv(env, nullptr, iv);
            aes_cbc_cipher.init(opMode, padding, j_key.get(), keyLen, j_iv.get());
        }

        // update
        JBinaryBlob output(env, outputDirect, outputArray);
        JBinaryBlob input(env, inputDirect, inputArray);

        return aes_cbc_cipher.update(input.get() + inputOffset, inputLen, output.get() + outputOffset, 0);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nUpdate(JNIEnv* env,
    jclass,
    jlong ctxPtr,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jint unprocessed_input,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCbcCipher aes_cbc_cipher(env, nullptr, ctxPtr, true);

        // update
        JBinaryBlob output(env, outputDirect, outputArray);
        JBinaryBlob input(env, inputDirect, inputArray);

        return aes_cbc_cipher.update(
            input.get() + inputOffset, inputLen, output.get() + outputOffset, unprocessed_input);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nUpdateFinal(JNIEnv* env,
    jclass,
    jlong ctxPtr,
    jboolean saveCtx,
    jobject inputDirect,
    jbyteArray inputArray,
    jint inputOffset,
    jint inputLen,
    jint unprocessedInput,
    jobject outputDirect,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        AesCbcCipher aes_cbc_cipher(env, nullptr, ctxPtr, saveCtx);

        int result = 0;

        // update
        JBinaryBlob output(env, outputDirect, outputArray);

        {
            JBinaryBlob input(env, inputDirect, inputArray);
            result = aes_cbc_cipher.update(
                input.get() + inputOffset, inputLen, output.get() + outputOffset, unprocessedInput);
        }

        // final
        result += aes_cbc_cipher.do_final(output.get() + outputOffset + result);

        return result;
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}
