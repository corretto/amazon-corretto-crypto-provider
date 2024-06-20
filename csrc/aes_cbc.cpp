// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

#define AES_CBC_BLOCK_SIZE_IN_BYTES 16
#define KEY_LEN_AES128              16
#define KEY_LEN_AES192              24
#define KEY_LEN_AES256              32

namespace AmazonCorrettoCryptoProvider {

static bool is_iso10126_padding(int padding)
{
    return padding == com_amazon_corretto_crypto_provider_AesCbcSpi_ISO10126_PADDING;
}

static bool is_encryption_mode(jint op_mode)
{
    return op_mode == com_amazon_corretto_crypto_provider_AesCbcSpi_ENC_MODE;
}

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

        // AWS-LC does not support AES-CBC with ISO10126 padding. ACCP supports ISO10126 by using AES-CBC with no
        // padding and implements the logic of padding/unpadding by itself.
        if (padding == com_amazon_corretto_crypto_provider_AesCbcSpi_ISO10126_PADDING) {
            padding = com_amazon_corretto_crypto_provider_AesCbcSpi_NO_PADDING;
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

    int extended_update(bool is_iso10126_padding,
        bool is_enc,
        jbyteArray j_last_block, /* j_last_block is AesCbcSpi.lastBlock. It's capacity is 17, where the last byte holds
                                    the number of bytes that it is holding at that point. */
        uint8_t const* input,
        int input_len,
        uint8_t* output,
        int unprocessed_input)
    {
        if (!is_iso10126_padding || is_enc) {
            return update(input, input_len, output, unprocessed_input);
        }

        // We are decrypting and padding is ISO10126. In this case, we must not decrypt the last block until do_final.

        // The last_block is used to store this information.
        JBinaryBlob last_block(jenv_, nullptr, j_last_block);
        // The last byte of last_block stores the number of bytes in it from the previous call.
        unsigned int const last_block_len = last_block.get()[AES_CBC_BLOCK_SIZE_IN_BYTES];

        // This is the total number of bytes that we have. Some must be stored in the last_block and the rest must be
        // passed to the cipher.
        unsigned int const all = last_block_len + input_len;

        if (all <= AES_CBC_BLOCK_SIZE_IN_BYTES) {
            // The total number of bytes is less than one full block size. We must save all bytes.

            // Appending the input to the end of last_block:
            std::memcpy(last_block.get() + last_block_len, input, input_len);
            // Updating the length of last_block:
            last_block.get()[AES_CBC_BLOCK_SIZE_IN_BYTES] = (uint8_t)all;

            // Returning 0 since no plaintext has been produced.
            return 0;
        }

        // We have more than 16 bytes in total. To find out how many bytes must be saved, we need to see if the total
        // number of bytes is a multiple of AES block size or not:

        unsigned int const rem = all % AES_CBC_BLOCK_SIZE_IN_BYTES;
        unsigned int save_bytes = 0;
        if (rem == 0) {
            // If the total number of bytes is a multiple of AES block size (16), then we must save one full block. We
            // cannot assume that more cipher text is to come: if this was the last update call, then after decrypting,
            // the padding must be removed from the output before returning the plaintext.
            save_bytes = AES_CBC_BLOCK_SIZE_IN_BYTES;
        } else {
            // Since the total number of bytes is not a multiple of AES block size, we can save the bytes that cause
            // misalignment and there is no need to save a full block. The total length of the cipher text in AES-CBC
            // mode is always a multiple of the block size (16): since the total number of bytes is not a multiple of
            // 16, more cipher text is to come.
            save_bytes = rem;
        }

        // We must process all the bytes except the last save_bytes in input:
        int result = update(last_block.get(), last_block_len, output, 0);
        result += update(input, input_len - save_bytes, output + result, last_block_len - result);

        // Save the last save_bytes of input into last_block and update its length:
        std::memcpy(last_block.get(), input + (input_len - save_bytes), save_bytes);
        last_block.get()[AES_CBC_BLOCK_SIZE_IN_BYTES] = save_bytes;

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

    int extended_do_final(
        bool is_iso10126_padding, bool is_enc, jbyteArray j_last_block, uint8_t* output, int unprocessed_input)
    {
        if (!is_iso10126_padding) {
            return do_final(output);
        }

        int result = 0;
        if (is_enc) {

            // The cipher is in encryption mode. We need to add padding.
            // The logic of padding is as follows:
            // 1. Find the number of bytes needed to make input's length a multiple of AES block size. Let's call this
            // number pl. This number is 16 in case the input was already a multiple of block size, otherwise, it's less
            // than 16.
            int pl = AES_CBC_BLOCK_SIZE_IN_BYTES - unprocessed_input;
            // 2. Generate (pl - 1) random bytes.
            uint8_t padding_bytes[AES_CBC_BLOCK_SIZE_IN_BYTES];
            if (RAND_bytes(padding_bytes, pl - 1) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "RAND_bytes failed.");
            }
            // 3. Set the last byte of the padding to pl.
            padding_bytes[pl - 1] = (uint8_t)pl;
            // 4. Pass the padding bytes to the cipher and continue encryption:
            result = update(padding_bytes, pl, output, unprocessed_input);
            // 5. Finalize the encryption
            result += do_final(output + result);

        } else {

            // The cipher is in decryption mode. We need to remove the padding.
            JBinaryBlob last_block(jenv_, nullptr, j_last_block);
            int last_block_len = last_block.get()[AES_CBC_BLOCK_SIZE_IN_BYTES];
            if (last_block_len != AES_CBC_BLOCK_SIZE_IN_BYTES) {
                throw java_ex(
                    EX_ERROR, "THIS SHOULD NOT BE REACHABLE: in the Java layer we ensure that this never happens.");
            }
            // First, we decrypt the last block.
            result = update(last_block.get(), last_block_len, output, unprocessed_input);
            if (do_final(output + result) != 0) {
                throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE: ISO10126 decrypt do_final produced output.");
            }
            // The last byte records the length of the padding.
            unsigned int size_of_padding = output[result - 1];
            if (size_of_padding > AES_CBC_BLOCK_SIZE_IN_BYTES) {
                // This can happen if wrong key is used or if the last block has been tampered.
                throw java_ex(EX_BADPADDING, "Bad padding");
            }
            // Remove padding by adjusting the output size.
            result -= size_of_padding;
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
    jbyteArray lastBlock,
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

        bool is_iso10126 = is_iso10126_padding(padding);
        bool is_enc = is_encryption_mode(opMode);

        // init
        {
            JBinaryBlob j_key(env, nullptr, key);
            JBinaryBlob j_iv(env, nullptr, iv);
            aes_cbc_cipher.init(opMode, padding, j_key.get(), keyLen, j_iv.get());
        }

        // update
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        int result = aes_cbc_cipher.extended_update(is_iso10126, is_enc, lastBlock, io_blobs.get_input() + inputOffset,
            inputLen, io_blobs.get_output() + outputOffset, 0);

        // final
        result += aes_cbc_cipher.extended_do_final(
            is_iso10126, is_enc, lastBlock, io_blobs.get_output() + outputOffset + result, inputLen - result);

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
    jbyteArray lastBlock,
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
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);

        return aes_cbc_cipher.extended_update(is_iso10126_padding(padding), is_encryption_mode(opMode), lastBlock,
            io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset, 0);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nUpdate(JNIEnv* env,
    jclass,
    jint opMode,
    jint padding,
    jlong ctxPtr,
    jbyteArray lastBlock,
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
        AesCbcCipher aes_cbc_cipher(env, nullptr, ctxPtr, true);

        // update
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);

        return aes_cbc_cipher.extended_update(is_iso10126_padding(padding), is_encryption_mode(opMode), lastBlock,
            io_blobs.get_input() + inputOffset, inputLen, io_blobs.get_output() + outputOffset, 0);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesCbcSpi_nUpdateFinal(JNIEnv* env,
    jclass,
    jint opMode,
    jint padding,
    jlong ctxPtr,
    jboolean saveCtx,
    jbyteArray lastBlock,
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

        bool is_iso10126 = is_iso10126_padding(padding);
        bool is_enc = is_encryption_mode(opMode);

        int up = unprocessedInput;

        // update
        JIOBlobs io_blobs(env, inputDirect, inputArray, outputDirect, outputArray);
        int result = aes_cbc_cipher.extended_update(is_iso10126, is_enc, lastBlock, io_blobs.get_input() + inputOffset,
            inputLen, io_blobs.get_output() + outputOffset, up);

        // final
        up = (inputLen + unprocessedInput) - result;
        result += aes_cbc_cipher.extended_do_final(
            is_iso10126, is_enc, lastBlock, io_blobs.get_output() + outputOffset + result, up);

        return result;

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return -1;
    }
}
