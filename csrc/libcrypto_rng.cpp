// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#define _DEFAULT_SOURCE // for getentropy

#include "config.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm> // for std::min
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"

using namespace AmazonCorrettoCryptoProvider;

bool libCryptoRngGenerateRandomBytes(uint8_t* buf, int len) noexcept
{
    /**
     * AWS LibCrypto provides a thread local, lazily initialized, FIPS Validated DRBG.
     *
     * There are purposefully no configuration options to this API around reseeding, mixing in external entropy, or
     * other options since AWS-LC has decided on it's own internal reseeding policies that take into account whether
     * FIPS mode is enabled, what entropy sources are available (RDRAND vs OS System Entropy), and whether process
     * fork detection is enabled or not (used to stop the internal DRBG state from being duplicated after a fork).
     *
     * Other LibCrypto's provide the same API, but may not be FIPS validated, and may not have as strong guarantee's
     * as AWS-LC.
     */
    int success = RAND_bytes(buf, len);

    return (success == 1);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_LibCryptoRng
 * Method:    generate
 * Signature: ([BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_LibCryptoRng_generate(
    JNIEnv* pEnv, jclass, jbyteArray byteArray, jint offset, jint length)
{
    try {
        raii_env env(pEnv);

        java_buffer byteBuffer = java_buffer::from_array(env, byteArray, offset, length);
        jni_borrow bytes(env, byteBuffer, "bytes");

        if (!libCryptoRngGenerateRandomBytes(bytes, length)) {
            bytes.zeroize();
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to generate random bytes");
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}
