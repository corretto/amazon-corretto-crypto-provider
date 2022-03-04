// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ACCP_LIBCRYPTO_RNG_H
#define ACCP_LIBCRYPTO_RNG_H 1

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include "generated-headers.h"
#include "util.h"
#include "compiler.h"

namespace AmazonCorrettoCryptoProvider {

class libcrypto_rng {
public:
    libcrypto_rng() noexcept;

    ~libcrypto_rng() noexcept;

    bool isInitialized() const noexcept { return initialized; }
    bool generateRandomBytes(uint8_t* bytes, int length) noexcept;

private:
    libcrypto_rng(const libcrypto_rng &) DELETE_IMPLICIT;
    libcrypto_rng &operator=(const libcrypto_rng &) DELETE_IMPLICIT;

    bool initialized;

    void initialize() noexcept;
};

}
#endif
