// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "generated-headers.h"
#include "env.h"
#include "buffer.h"


using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_throwException
  (JNIEnv *pEnv, jclass)
{
    try {
        raii_env env(pEnv);

        throw_java_ex("java/lang/IllegalArgumentException", "Test exception message");
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

namespace {
    void check_get_result(uint8_t *destbuf, int offset, int off2, int len2) {
        for (int i = 0; i < len2; i++) {
            uint8_t expected = i + offset + off2;
            if (destbuf[i] != (uint8_t)(i + offset + off2)) {
                char *message = NULL;
                int rv = asprintf(&message, "Bad value in input array; i=%d val=%02x expect=%02x",
                    i, destbuf[i] & 0xFFU, (unsigned int)expected);
                if (rv == -1) {
                    throw_java_ex("java/lang/AssertionError", "Bad value in input array; alloation failure when formatting error message");
                } else {
                    std::string str(message);
                    free(message);
                    throw_java_ex("java/lang/AssertionError", str);
                }
            }
        }
    }

    void init_for_put(uint8_t *buf, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = 100+i;
        }
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_getBytes
  (JNIEnv *pEnv, jclass, jbyteArray array, jint offset, jint length, jint off2, jint len2)
{
    try {
        raii_env env(pEnv);
        java_buffer buffer = java_buffer::from_array(env, array, offset, length);
        uint8_t *destbuf = reinterpret_cast<uint8_t *>(alloca(std::max(1, len2)));

        buffer.get_bytes(env, destbuf, off2, len2);
        check_get_result(destbuf, offset, off2, len2);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_putBytes
  (JNIEnv *pEnv, jclass, jbyteArray array, jint offset, jint length, jint off2, jint len2)
{
    try {
        raii_env env(pEnv);
        java_buffer buffer = java_buffer::from_array(env, array, offset, length);
        
        size_t actual_len = std::max(1, len2);
        uint8_t *destbuf = reinterpret_cast<uint8_t *>(alloca(actual_len));
        init_for_put(destbuf, actual_len);

        buffer.put_bytes(env, destbuf, off2, len2);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_putBytesLocked
  (JNIEnv *pEnv, jclass, jbyteArray array, jint offset, jint length, jint off2, jint len2)
{
    try {
        raii_env env(pEnv);
        java_buffer buffer = java_buffer::from_array(env, array, offset, length);
        jni_borrow lock(env, java_buffer::from_array(env, env->NewByteArray(1)), "lock");
        
        size_t actual_len = std::max(1, len2);
        uint8_t *destbuf = reinterpret_cast<uint8_t *>(alloca(actual_len));
        init_for_put(destbuf, actual_len);

        buffer.put_bytes(env, destbuf, off2, len2);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_getBytesLocked
  (JNIEnv *pEnv, jclass, jbyteArray array, jint offset, jint length, jint off2, jint len2)
{
    try {
        raii_env env(pEnv);
        java_buffer buffer = java_buffer::from_array(env, array, offset, length);
        jni_borrow lock(env, java_buffer::from_array(env, env->NewByteArray(1)), "lock");

        uint8_t *destbuf = reinterpret_cast<uint8_t *>(alloca(std::max(1, len2)));

        buffer.get_bytes(env, destbuf, off2, len2);
        check_get_result(destbuf, offset, off2, len2);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}


JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_borrowCheckRange
  (JNIEnv *pEnv, jclass, jbyteArray array, jint offset, jint length, jint off2, jint len2)
{
    try {
        raii_env env(pEnv);
        java_buffer buffer = java_buffer::from_array(env, array, offset, length);
        jni_borrow borrow(env, buffer, "borrowCheckRange");

        borrow.check_range(off2, len2);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}


