// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "rand.h"
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
  ERR_load_crypto_strings();
  OpenSSL_add_all_digests();

  // Install our own RNG
  registerOpensslDrbg();

  // seed the PRNG
  RAND_poll();
}

}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    initialize();
    return JNI_VERSION_1_4;
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
