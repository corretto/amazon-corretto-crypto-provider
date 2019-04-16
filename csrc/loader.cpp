// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// NOTE: This must be kept in sync with the value in Java.
#define PROVIDER_VERSION_STRING "1.0.2"

namespace {

static pthread_mutex_t *lock_cs;
static int numLocks;

void locking_callback(int mode, int type, const char* file, int line) {
  if (mode & CRYPTO_LOCK) {
    if (pthread_mutex_lock(&(lock_cs[type])) != 0) {
      abort();
    }
  } else {
    if (pthread_mutex_unlock(&(lock_cs[type])) != 0) {
      abort();
    }
  }
}

unsigned long thread_id_callback() {
  return (unsigned long) pthread_self();
}

void initialize() {
  // While there is a chance of bad threading, this is the best we can do
  if (CRYPTO_get_locking_callback() == NULL) {
    // No locking enabled, register our own
    numLocks = CRYPTO_num_locks();
    lock_cs = (pthread_mutex_t*) OPENSSL_malloc(numLocks * sizeof(pthread_mutex_t));
    if (!lock_cs) {
        // We can't actually throw an exception here
        // TODO: Report this in a safe manner
        fprintf(stderr, "Unable to allocate memory for locks\n");
        abort();
    }
    // lock_cs is purposefully leaked since we will need it for as long as this application runs
    // and we do not have a reliable way to clean it up upon termination

    for (int x = 0; x < numLocks; x++) {
      pthread_mutex_init(&lock_cs[x], NULL);
    }

    // primary callback set
    CRYPTO_set_locking_callback(locking_callback);
    // Take the lock and set the threadid callback
    CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
    
    CRYPTO_set_id_callback(thread_id_callback);

    // Release the lock
    CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK); 
  }
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

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    for (int x = 0; x < numLocks; x++) {
      pthread_mutex_destroy(&lock_cs[x]);
      OPENSSL_free(lock_cs);
    }
}

JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_Loader_getNativeLibraryVersion(
  JNIEnv *pEnv,
  jclass
)
{
    try {
        raii_env env(pEnv);

        return env->NewStringUTF(PROVIDER_VERSION_STRING);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }

}
