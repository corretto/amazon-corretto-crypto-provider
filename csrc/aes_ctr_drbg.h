// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef AES_CTR_DRBG_H
#define AES_CTR_DRBG_H 1

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include "generated-headers.h"
#include "util.h"
#include "compiler.h"

#define DRBG_BLOCK_SIZE 16
#define DRBG_KEY_SIZE 32
#define DRBG_SEED_SIZE DRBG_BLOCK_SIZE + DRBG_KEY_SIZE

namespace AmazonCorrettoCryptoProvider {

class aes_256_drbg {
public:
    // If initialized is false, then this constructor has failed.
    aes_256_drbg(const SecureBuffer<uint8_t, DRBG_SEED_SIZE> &seed) noexcept;
    aes_256_drbg(const SecureBuffer<uint8_t, DRBG_SEED_SIZE> &seed, const std::vector<uint8_t, SecureAlloc<uint8_t> > &testData) noexcept;

    ~aes_256_drbg() noexcept;

    bool isInitialized() const noexcept { return initialized; }
    bool reseed(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept;
    bool generateRandomBytes(uint8_t* bytes, int length) noexcept;

private:
    aes_256_drbg() DELETE_IMPLICIT;
    aes_256_drbg(const aes_256_drbg &) DELETE_IMPLICIT;
    aes_256_drbg &operator=(const aes_256_drbg &) DELETE_IMPLICIT;

    bool initialized;
    bool ctxNeedsCleanup;
    EVP_CIPHER_CTX *ctx;
    SecureBuffer<uint8_t, DRBG_BLOCK_SIZE> v;
    // For testing purposes only
    int fake_entropy_pos;
    int fake_entropy_len;
    uint8_t* fake_entropy;

    void initialize(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept;
    bool internalGenerateBytes(uint8_t* buf, int len) noexcept;
    bool update(const SecureBuffer<uint8_t, DRBG_SEED_SIZE>& seed) noexcept;
    void incrementCtr() noexcept;

    // Retrieves entropy from the underlying entropy source
    int get_entropy(uint8_t* buf, int len) noexcept;
};

}
#endif
