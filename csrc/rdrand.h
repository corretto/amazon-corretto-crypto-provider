// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef RDRAND_H
#define RDRAND_H

#include <stdlib.h>
#include <stdint.h>
#include "compiler.h"
#include "config.h"

namespace AmazonCorrettoCryptoProvider {

bool rng_rdrand(uint64_t *out);
bool rng_rdseed(uint64_t *out);
bool rdseed(unsigned char *buf, int len);
bool rdrand(unsigned char *buf, int len);
bool supportsRdRand();
bool supportsRdSeed();

}

#ifdef ENABLE_NATIVE_TEST_HOOKS
extern "C" {
    extern bool (*hook_rdrand)(uint64_t *out);
    extern bool (*hook_rdseed)(uint64_t *out);
}
#endif

#endif
