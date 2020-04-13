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

#ifdef HAVE_GETENTROPY_IN_SYSRANDOM
#include <sys/random.h>
#endif

#include "generated-headers.h"
#include "util.h"
#include "rdrand.h"
#include "env.h"
#include "buffer.h"
#include "aes_ctr_drbg.h"

/* The maximum size of any one request: from NIST SP800-90A 10.2.1 Table 3 */
#define DRBG_GENERATE_LIMIT com_amazon_corretto_crypto_provider_AesCtrDrbg_MAX_SINGLE_REQUEST

#ifndef O_CLOEXEC
#ifdef __linux__
// We're building on an old libc. This is what this flag is defined on newer linuxes.
#define O_CLOEXEC 0x00080000
#else
// We're on some other posixy system which doesn't support O_CLOEXEC. Define it to be zero;
// we'll go into the fcntl fallback path instead.
#define O_CLOEXEC 0
#endif // __linux__
#endif // O_CLOEXEC

using namespace AmazonCorrettoCryptoProvider;

namespace {
pthread_mutex_t getentropy_mutex = PTHREAD_MUTEX_INITIALIZER;
int urandom_fd = -1;

bool drbg_getentropy(void *buffer, size_t length) {
#ifdef HAVE_GETENTROPY
    int rv = getentropy(buffer, length);
    if (likely(rv == 0) || errno != ENOSYS) {
        // The getentropy call was available; return success if it
        // gave us a successful return.
        return !rv;
    }
#endif

    // Fallback path for when getentropy is unavailable
    bool success = false;
    int mutex_error = 0;
    uint8_t *bufp = reinterpret_cast<uint8_t *>(buffer);

    if (unlikely(mutex_error = pthread_mutex_lock(&getentropy_mutex))) {
        errno = mutex_error;
        perror("pthread_mutex_lock");
        abort(); // mutex failure - don't even try to recover
    }

    if (unlikely(urandom_fd < 0)) {
        if (O_CLOEXEC) {
            // If O_CLOEXEC is undefined, make sure we go into the fallback path
            // which will do a workaround using fcntl.
            urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        }

        if (unlikely(urandom_fd < 0)) {
            if (errno == EINVAL || errno == ENOSYS) {
                // We might be on an old kernel that doesn't support O_CLOEXEC.
                // Try again and use fcntl instead. This is subject to an unavoidable
                // race condition in which the process forks before we can set the CLOEXEC
                // flag, which is why O_CLOEXEC was introduced in the first place.
                int flags;

                urandom_fd = open("/dev/urandom", O_RDONLY);
                if (urandom_fd >= 0) {
                    flags = fcntl(F_GETFD, urandom_fd);
                    if (flags == -1) {
                        close(urandom_fd);
                        urandom_fd = -1;
                    } else {
                        if (-1 == fcntl(F_SETFD, urandom_fd, flags | FD_CLOEXEC)) {
                            close(urandom_fd);
                            urandom_fd = -1;
                        }
                    }
                }
            }
        }
        // If our workaround failed we'll still have urandom_fd = -1

        if (unlikely(urandom_fd < 0)) {
            goto out;
        }
    }

    while (length) {
        ssize_t rv = read(urandom_fd, bufp, length);
        if (rv < 0) {
            goto out;
        }
        length -= rv;
        bufp += rv;
    }

    success = true;
out:
    if (!success) {
        secureZero(buffer, length);
    }

    if (unlikely(mutex_error = pthread_mutex_unlock(&getentropy_mutex))) {
        errno = mutex_error;
        perror("pthread_mutex_unlock");
        abort(); // unexpected mutex failure - can't recover
    }

    return success;
}

}

// This ctor for testing only
aes_256_drbg::aes_256_drbg(const SecureBuffer<uint8_t, DRBG_SEED_SIZE> &seed, const std::vector<uint8_t, SecureAlloc<uint8_t> > &testData) noexcept {
    initialized = false;
    ctxNeedsCleanup = false;

    fake_entropy_len = testData.size();
    fake_entropy = new uint8_t[fake_entropy_len];
    memcpy(fake_entropy, &testData[0], fake_entropy_len);
    fake_entropy_pos = 0;

    initialize(seed);
}

aes_256_drbg::aes_256_drbg(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept {
    initialized = false;
    ctxNeedsCleanup = false;

    fake_entropy_len = 0;
    fake_entropy = NULL;
    fake_entropy_pos = 0;

    initialize(seed);
}

aes_256_drbg::~aes_256_drbg() noexcept {
    if (ctxNeedsCleanup) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (fake_entropy) {
        delete[] fake_entropy;
    }
}

void aes_256_drbg::initialize(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept {
    static const uint8_t zero_key[DRBG_KEY_SIZE] = { 0 };

    ctx = EVP_CIPHER_CTX_new();
    if (unlikely(!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, zero_key, NULL))) {
        return; // failed, we'll leave it uninitialized
    }

    ctxNeedsCleanup = true;

    if (unlikely(!update(seed))) {
        EVP_CIPHER_CTX_free(ctx);
        ctxNeedsCleanup = false;
        return; // leave uninitialized
    }

    if (!fake_entropy) {
        SecureBuffer<uint8_t, DRBG_SEED_SIZE> rdseed_data;

        if (!rdseed(rdseed_data.buf, sizeof(rdseed_data.buf))
         || !update(rdseed_data)
        ) {
            // CPU claimed to have rdseed support but failed to generate entropy;
            // bail out.
            EVP_CIPHER_CTX_free(ctx);
            ctxNeedsCleanup = false;
            return; // leave uninitialized
        }
    }

    initialized = true;
}

int aes_256_drbg::get_entropy(uint8_t* buf, int len) noexcept {
    if (fake_entropy) {
        if (len > fake_entropy_len - fake_entropy_pos) {
            return 0;
        } else {
            memcpy(buf, fake_entropy + fake_entropy_pos, len);
            fake_entropy_pos += len;
            return 1;
        }
    } else {
        return rdrand(buf, len);
    }
}

bool aes_256_drbg::update(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept {
    SecureBuffer<uint8_t, DRBG_SEED_SIZE> temp;

    if (unlikely(!internalGenerateBytes(temp, DRBG_SEED_SIZE))) {
        return false;
    }
    fast_xor(temp, seed, DRBG_SEED_SIZE);

    if (unlikely(!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, temp, NULL))) {
        return false;
    }
    memcpy(v, temp + DRBG_KEY_SIZE, DRBG_BLOCK_SIZE);
    return true;
}

bool aes_256_drbg::reseed(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept {
    SecureBuffer<uint8_t, DRBG_SEED_SIZE> entropy;

    if (unlikely(!isInitialized())) {
        return false;
    }

    if (unlikely(!get_entropy(entropy, DRBG_SEED_SIZE))) {
        return false;
    }

    fast_xor(entropy, seed, DRBG_SEED_SIZE);
    return !!update(entropy);
}

void aes_256_drbg::incrementCtr() noexcept {
    uint64_t *ctrp = reinterpret_cast<uint64_t*>(v.buf);
    ctrp[1] = hostToBigEndian64(1 + bigEndianToHost64(ctrp[1]));
    if (unlikely(ctrp[1] == 0)) {
        ctrp[0] = hostToBigEndian64(1 + bigEndianToHost64(ctrp[0]));
    }
}

bool aes_256_drbg::internalGenerateBytes(uint8_t* buf, int len) noexcept {
    SecureBuffer<uint8_t, DRBG_BLOCK_SIZE> block;

    int generated = 0;

    if (unlikely(len > DRBG_GENERATE_LIMIT)) {
        return false;
    }

    while (generated < len) {
        incrementCtr();
        int outLen;
        if (unlikely(!EVP_EncryptUpdate(ctx, block, &outLen, v, DRBG_BLOCK_SIZE))) {
            return false;
        }
        int to_write = std::min(outLen, len - generated);
        memcpy(buf + generated, block, to_write);
        generated += to_write;
    }
    return true;
}

bool aes_256_drbg::generateRandomBytes(uint8_t *buf, int len) noexcept {
    static const SecureBuffer<uint8_t, DRBG_SEED_SIZE> zero_seed;

    if (unlikely(!isInitialized())) {
        return false;
    }

    if (unlikely(len > DRBG_GENERATE_LIMIT)) {
        return false;
    }

    return likely(reseed(zero_seed) && internalGenerateBytes(buf, len) && update(zero_seed));
}

/*
 * Class:     com_amazon_corretto_crypto_provider_AesCtrDrbg
 * Method:    instantiate
 * Signature: ([B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_AesCtrDrbg_instantiate(
        JNIEnv *pEnv, jclass, jbyteArray seedArr, jbyteArray fakeDataArr) {
    try {
        raii_env env(pEnv);

        SecureBuffer<uint8_t, DRBG_SEED_SIZE> seedBuf;
        if (likely(!seedArr)) {
            if (!drbg_getentropy(seedBuf.buf, sizeof(seedBuf.buf))) {
                throw java_ex(EX_RUNTIME_CRYPTO, "Failed to get initial seed entropy");
            }
        } else {
            // For tests only - load explicit seed
            java_buffer seed = java_buffer::from_array(env, seedArr);

            if (unlikely(seed.len() != DRBG_SEED_SIZE)) {
                throw java_ex(EX_RUNTIME_CRYPTO, "Incorrect seed length");
            }

            seed.get_bytes(env, seedBuf.buf, 0, sizeof(seedBuf.buf));
        }

        // Sanity check - reject a zero seed
        const static uint8_t ZERO_SEED[DRBG_SEED_SIZE] = { 0 };
        if (!memcmp(ZERO_SEED, seedBuf.buf, DRBG_SEED_SIZE)) {
            throw java_ex(EX_RUNTIME_CRYPTO, "Assertion error: Seed is zero");
        }

        aes_256_drbg *result;
        if (unlikely(fakeDataArr)) {
            // For tests only - load fake entropy
            java_buffer fakeData = java_buffer::from_array(env, fakeDataArr);

            std::vector<uint8_t, SecureAlloc<uint8_t> > fakeDataVec = fakeData.to_vector(env);

            result = new aes_256_drbg(seedBuf, fakeDataVec);
        } else {
            result = new aes_256_drbg(seedBuf);
        }

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
 * Class:     com_amazon_corretto_crypto_provider_AesCtrDrbg
 * Method:    reseed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesCtrDrbg_reseed(
        JNIEnv *pEnv, jclass, jlong ctx, jbyteArray seedArray) {
    try {
        raii_env env(pEnv);

        if (unlikely(!ctx)) {
            throw java_ex(EX_NPE, "Context must not be null");
        }

        aes_256_drbg* state = (aes_256_drbg*) ctx;

        SecureBuffer<uint8_t, DRBG_SEED_SIZE> seedBuf;
        java_buffer seed = java_buffer::from_array(env, seedArray);

        if (unlikely(seed.len() != DRBG_SEED_SIZE)) {
            throw java_ex(EX_RUNTIME_CRYPTO, "Bad seed size");
        }

        seed.get_bytes(env, seedBuf.buf, 0, DRBG_SEED_SIZE);

        if (unlikely(!state->reseed(seedBuf))) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to reseed DRBG");
        }
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_AesCtrDrbg
 * Method:    generate
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesCtrDrbg_generate(
        JNIEnv *pEnv, jclass, jlong ctx, jbyteArray byteArray, jint offset,
        jint length) {
    try {
        raii_env env(pEnv);

        if (unlikely(!ctx)) {
            throw java_ex(EX_NPE, "Context must not be null");
        }

        aes_256_drbg* state = (aes_256_drbg*) ctx;

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
 * Class:     com_amazon_corretto_crypto_provider_AesCtrDrbg
 * Method:    releaseState
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesCtrDrbg_releaseState(
        JNIEnv * env, jclass, jlong ctx) {
    if (ctx) {
        aes_256_drbg* state = (aes_256_drbg*) ctx;
        delete state;
    }
}

