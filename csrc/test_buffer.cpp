// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "test_utils.h"
#include "util.h"
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

// cleanse_and_stash is the testable seam for JByteArrayCritical's wipe-on-copy logic.
// Exercising it directly avoids the need for a real JVM that returns an array copy from
// GetPrimitiveArrayCritical (which HotSpot generally does not do).

void test_cleanse_and_stash_copies_then_zeros_source()
{
    constexpr size_t LEN = 32;
    uint8_t src[LEN];
    for (size_t i = 0; i < LEN; i++) {
        src[i] = static_cast<uint8_t>(i + 1); // nonzero pattern
    }

    std::vector<uint8_t, SecureAlloc<uint8_t> > stash;
    JByteArrayCritical::cleanse_and_stash(src, static_cast<jsize>(LEN), stash);

    if (stash.size() != LEN) {
        FAIL();
        return;
    }
    for (size_t i = 0; i < LEN; i++) {
        if (stash[i] != static_cast<uint8_t>(i + 1)) {
            FAIL();
            return;
        }
        if (src[i] != 0) {
            FAIL();
            return;
        }
    }
}

void test_cleanse_and_stash_zero_length_is_noop()
{
    uint8_t src[1] = { 0x42 };
    std::vector<uint8_t, SecureAlloc<uint8_t> > stash;
    JByteArrayCritical::cleanse_and_stash(src, 0, stash);

    if (!stash.empty()) {
        FAIL();
        return;
    }
    // src is untouched on zero-length
    if (src[0] != 0x42) {
        FAIL();
        return;
    }
}

void test_cleanse_and_stash_overwrites_existing_stash()
{
    constexpr size_t LEN = 8;
    uint8_t src[LEN] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    std::vector<uint8_t, SecureAlloc<uint8_t> > stash;
    // Pre-populate with different contents to verify assign() replaces them.
    stash.assign(LEN * 2, 0x99);

    JByteArrayCritical::cleanse_and_stash(src, static_cast<jsize>(LEN), stash);

    if (stash.size() != LEN) {
        FAIL();
        return;
    }
    static const uint8_t expected[LEN] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    for (size_t i = 0; i < LEN; i++) {
        if (stash[i] != expected[i]) {
            FAIL();
            return;
        }
        if (src[i] != 0) {
            FAIL();
            return;
        }
    }
}

} // anon namespace

int main()
{
    BEGIN_TEST();
    RUNTEST(test_cleanse_and_stash_copies_then_zeros_source);
    RUNTEST(test_cleanse_and_stash_zero_length_is_noop);
    RUNTEST(test_cleanse_and_stash_overwrites_existing_stash);
    END_TEST();
}
