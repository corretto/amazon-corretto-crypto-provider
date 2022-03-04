// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _DEFAULT_SOURCE // for getentropy

#include "config.h"

#include <algorithm> // for std::min
#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

#include "generated-headers.h"
#include "util.h"
#include "rdrand.h"
#include "env.h"
#include "buffer.h"
#include "libcrypto_rng.h"

using namespace AmazonCorrettoCryptoProvider;

libcrypto_rng::libcrypto_rng() noexcept {
    initialize();
}

libcrypto_rng::~libcrypto_rng() noexcept {
    initialized = false;
}

void libcrypto_rng::initialize() noexcept {
    /**
     * AWS-LC will lazily initialize itself on first use. There is no API to force the RNG to initialize itself.
     *
     * Keep this method stub in case different initialization logic is needed for different LibCrypto's.
     */
    initialized = true;
}

bool libcrypto_rng::generateRandomBytes(uint8_t *buf, int len) noexcept {
    /**
     * AWS LibCrypto provides a thread local, lazily initialized, FIPS Validated DRBG that is seeded with CPU Jitter
     * entropy on first use. This API also mixes in more entropy from the fastest available source after every call.
     * If available it will use x86 RDRAND instruction, or otherwise use the OS system entropy (Eg /dev/urandom/) to
     * keep prediction resistance.
     *
     * There are purposefully no configuration options to this API around reseeding, mixing in external entropy, or
     * other options in order to guarantee a simple and safe API to users.
     *
     * Other LibCrypto's provide the same API, but may not be FIPS validated, and may not have as strong guarantee's
     * as AWS-LC.
     */
    int success = RAND_bytes(buf, len);

    return (success ==  1);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_LibCryptoRng
 * Method:    instantiate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_LibCryptoRng_instantiate(
        JNIEnv *pEnv, jclass) {
    try {
        raii_env env(pEnv);

        libcrypto_rng *result;
        result = new libcrypto_rng();

        if (unlikely(!result->isInitialized())) {
            delete result;
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unknown error in DRBG initialization");
        }

        return (jlong) result;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_LibCryptoRng
 * Method:    generate
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_LibCryptoRng_generate(
        JNIEnv *pEnv, jclass, jlong ctx, jbyteArray byteArray, jint offset,
        jint length) {
    try {
        raii_env env(pEnv);

        if (unlikely(!ctx)) {
            throw java_ex(EX_NPE, "Context must not be null");
        }

        libcrypto_rng* state = (libcrypto_rng*) ctx;

        java_buffer byteBuffer = java_buffer::from_array(env, byteArray, offset, length);
        jni_borrow bytes(env, byteBuffer, "bytes");

        if (!state->generateRandomBytes(bytes, length)) {
            bytes.zeroize();
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to generate random bytes");
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_LibCryptoRng
 * Method:    releaseState
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_LibCryptoRng_releaseState(
        JNIEnv * env, jclass, jlong ctx) {
    if (ctx) {
        libcrypto_rng* state = (libcrypto_rng*) ctx;
        delete state;
    }
}

