// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "env.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)
// thread support enabled
#else
#error Openssl must be compiled with thread support
#endif

// Right now we only support PTHREAD
#include <pthread.h>

// https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_VERSION_NUMBER.html
// 0xMNNFFPPS : major minor fix patch status
// 0x1010107f == v1.1.1g release
#define LIBCRYPTO_MAJOR_MINOR_VERSION_MASK 0xFFF00000

#define LIBCRYPTO_EXACT_VERSION_MATCH       0
#define LIBCRYPTO_FUZZY_VERSION_MATCH       1

static char accp_loader_exception_msg[256] = {0};

using namespace AmazonCorrettoCryptoProvider;

namespace {
void initialize() {
  CRYPTO_library_init();
  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();

  // seed the PRNG
  RAND_poll();
}

}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    initialize();
    return JNI_VERSION_1_4;
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_isFipsMode(JNIEnv*, jclass)
{
  return FIPS_mode() == 1 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_Loader_getNativeLibraryVersion(
  JNIEnv *pEnv,
  jclass
)
{
    try {
        raii_env env(pEnv);

        return env->NewStringUTF(STRINGIFY(PROVIDER_VERSION_STRING));
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }

}

void accpValidateLibcryptoVersion(bool fuzzyMatch) {
    unsigned long libcrypto_compiletime_version = OPENSSL_VERSION_NUMBER;
    unsigned long libcrypto_runtime_version = OpenSSL_version_num();

    if (fuzzyMatch) {
        libcrypto_compiletime_version &= LIBCRYPTO_MAJOR_MINOR_VERSION_MASK;
        libcrypto_runtime_version     &= LIBCRYPTO_MAJOR_MINOR_VERSION_MASK;
    }

    if (libcrypto_compiletime_version != libcrypto_runtime_version) {
        memset(accp_loader_exception_msg, 0, sizeof(accp_loader_exception_msg));
        snprintf(accp_loader_exception_msg, sizeof(accp_loader_exception_msg),
                "Runtime libcrypto version does not match compile-time version. Expected: 0x%08lX , Actual: 0x%08lX",
                libcrypto_compiletime_version, libcrypto_runtime_version);
        throw java_ex(EX_RUNTIME_CRYPTO, accp_loader_exception_msg);
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_validateLibcryptoExactVersionMatch(JNIEnv* pEnv, jclass)
{
    try {
        accpValidateLibcryptoVersion(LIBCRYPTO_EXACT_VERSION_MATCH);
        return JNI_TRUE;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_validateLibcryptoFuzzyVersionMatch(JNIEnv* pEnv, jclass)
{
    try {
        accpValidateLibcryptoVersion(LIBCRYPTO_FUZZY_VERSION_MATCH);
        return JNI_TRUE;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    return JNI_FALSE;
}
