// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/rand.h>
#include <pthread.h>

#include <stdio.h>

#include "generated-headers.h"
#include "util.h"
#include "env.h"
#include "buffer.h"
#include "aes_ctr_drbg.h"
#include "rand.h"
#include "rdrand.h"

using namespace AmazonCorrettoCryptoProvider;

namespace {

static void seed(const void *buf, int num);
static int bytes(uint8_t *buf, size_t num);
static void add(const void *buf, int num, double entropy);
static int pseudorand(uint8_t *buf, size_t num);
static void cleanup();
static int status();

static pthread_mutex_t drbg_lock = PTHREAD_MUTEX_INITIALIZER;
static aes_256_drbg* drbg = NULL;
static bool healthy = false;

RAND_METHOD drbg_rand_methods={
    seed,
    bytes,
    cleanup,
    add,
    pseudorand,
    status
};

void cleanup() {
    pthread_lock_auto lock(&drbg_lock);
    if (drbg) {
        return;
    }
    delete drbg;
    drbg = NULL;
    healthy = false;
}

int pseudorand(uint8_t *buf, size_t num) {
    return bytes(buf, num);
}

int bytes(uint8_t *buf, size_t num) {
    pthread_lock_auto lock(&drbg_lock);
    if (!drbg || !healthy) {
        return 0;
    }
    if (drbg->generateRandomBytes(buf, num)) {
        return 1;
    } else {
        healthy = false;
        return 0;
    }
}

void add(const void *buf, int num, double entropy) {
    seed(buf, num);
}

void seed(const void *buf, int num) {
    pthread_lock_auto lock(&drbg_lock);
    if (!drbg || !healthy) {
        return;
    }

    SecureBuffer<uint8_t, DRBG_SEED_SIZE> seed;
    const uint8_t* start = (const uint8_t*) buf;
    while (num > 0) {
        int len = num > DRBG_SEED_SIZE ? DRBG_SEED_SIZE : num;
        memcpy(seed.buf, start, len);
        if (!drbg->reseed(seed)) {
            healthy = false;
            return;
        }
        start += len;
        num -= len;
    }
    return;
}

int status() {
    pthread_lock_auto lock(&drbg_lock);
    return healthy ? 1 : 0;
}

void initialize_drbg() {
    pthread_lock_auto lock(&drbg_lock);
    if (drbg) {
        delete drbg;
        drbg = NULL;
    }
    healthy = false;

    SecureBuffer<uint8_t, DRBG_SEED_SIZE> seed;
    if (!rdrand(seed.buf, DRBG_SEED_SIZE)) {
        // We don't have a JNI environment here (we're in JNI_OnLoad) so we can't throw exceptions.
        // TODO: Build a reporting path for these errors
        // fprintf(stderr, "Unable to get seed entropy");
        return;
    }

    drbg = new aes_256_drbg(seed);
    if (!drbg->isInitialized()) {
        delete drbg;
        //fprintf(stderr, "Unable to initialize DRBG");
        return;
    }

    healthy = true;
}

} // Anonymous namespace

namespace AmazonCorrettoCryptoProvider {

void registerOpensslDrbg() {
    if (supportsRdRand()) {
        initialize_drbg();
        if (status()) {
            RAND_set_rand_method(&drbg_rand_methods);
        } else {
            cleanup();
        }
    }
}

}
