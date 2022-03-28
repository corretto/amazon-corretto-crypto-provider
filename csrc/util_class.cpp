// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// JNI methods needed by the Java Utils class rather than generic utilities needed by our code.

#include "generated-headers.h"

#include "util.h"
#include "env.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

extern "C" {

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getNativeBufferOffset
 * Signature: (Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)J
 */

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getNativeBufferOffset
  (JNIEnv *env, jclass, jobject bufA, jobject bufB)
{
    jlong no_overlap = (jlong)0x80000000;

    void *pA = env->GetDirectBufferAddress(bufA);
    void *pB = env->GetDirectBufferAddress(bufB);

    if (!pA || !pB) return no_overlap;

    jlong lenA = env->GetDirectBufferCapacity(bufA);
    jlong lenB = env->GetDirectBufferCapacity(bufB);

    uintptr_t vA = (uintptr_t)pA;
    uintptr_t vB = (uintptr_t)pB;

    ptrdiff_t diff = vB - vA;
    if (diff > 0 && diff >= lenA) {
        // B is located after A's end, so there's no real overlap
        return no_overlap;
    }

    if (diff < 0 && -diff >= lenB) {
        // A is located after B's end, so no real overlap
        return no_overlap;
    }

    // diff should be within jint's bounds now, as direct buffers can't be larger
    // than can be represented by an int
    assert(diff < (1L << 31) && diff >= -(1L << 31));

    return diff;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getEvpMdFromName
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getEvpMdFromName(
  JNIEnv *pEnv,
  jclass,
  jstring mdName) {
    try {
      raii_env env(pEnv);
      return reinterpret_cast<jlong>(digestFromJstring(env, mdName));
    } catch (java_ex &ex)
    {
      ex.throw_to_java(pEnv);
      return 0;
    }
  }

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getDigestLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getDigestLength(JNIEnv *, jclass, jlong evpMd) {
  return EVP_MD_size(reinterpret_cast<const EVP_MD *>(evpMd));
}
}
