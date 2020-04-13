// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <stddef.h>
#include <string>
#include <sstream>
#include <openssl/err.h>
#include <cassert>
#include "generated-headers.h"

#include "util.h"
#include "env.h"

#define CLASSNOTFOUND_TYPE "java/lang/NoClassDefFoundError"

namespace AmazonCorrettoCryptoProvider {

unsigned long drainOpensslErrors() {
  unsigned long result = 0;
  unsigned long tmp = ERR_get_error();
  while (tmp != 0) {
    result = tmp;
    tmp = ERR_get_error();
  }
  return result;
}

std::string formatOpensslError(unsigned long errCode, const char *fallback) {
  if (errCode) {
    char buffer[256];
    ERR_error_string_n(errCode, buffer, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';
    return std::string(buffer);
  } else {
    return std::string(fallback);
  }
}
} // namespace

extern "C" {

// Java Utils method implementations
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
}
