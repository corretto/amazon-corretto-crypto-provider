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


JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_validateLibcryptoExactVersionMatch(JNIEnv* pEnv, jclass)
{
    char msg_buffer[256] = {0};

    try {
        const unsigned long libcrypto_compiletime_version = OPENSSL_VERSION_NUMBER;
        const unsigned long libcrypto_runtime_version = OpenSSL_version_num();

        if (libcrypto_compiletime_version != libcrypto_runtime_version) {
            snprintf(msg_buffer, sizeof(msg_buffer), "Runtime libcrypto version does not match compile-time version. "
                "Expected: 0x%08lX , Actual: 0x%08lX", libcrypto_compiletime_version, libcrypto_runtime_version);
            throw java_ex(EX_RUNTIME_CRYPTO, msg_buffer);
        }

        return JNI_TRUE;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    return JNI_FALSE;
}
