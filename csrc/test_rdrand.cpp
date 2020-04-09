// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * Standalone test harness for rdrand/rdseed functionality and their retry loops.
 *
 * Because we don't want to leave mutable function pointers lying around in static memory,
 * we use code patching to replace rdrand/rdseed with test variants.
 */

#undef NDEBUG

#include "env.h"
#include "rdrand.h"
#include "test_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

using namespace AmazonCorrettoCryptoProvider;

namespace {

uint64_t counter = 0;

bool rng_failing_after(uint64_t *out) {
    if (counter > 0) {
        counter--;
        return true;
    }
    return false;
}

bool rng_alternating(uint64_t *out) {
    if (!(++counter & 1)) {
        return false;
    }

    *out = counter;
    return true;
}

bool rng_stuck_zero(uint64_t *out) {
    *out = 0;
    return true;
}

bool rng_stuck_ff(uint64_t *out) {
    *out = UINT64_MAX;
    return true;
}

void when_rng_flaky_retry_works() {
    static const uint8_t expected1[] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05
    };
    static const uint8_t expected2[] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x05
    };
    static uint8_t buf[sizeof(expected1)];

    hook_rdrand = rng_alternating;
    hook_rdseed = rng_alternating;

    counter = 0;

    TEST_ASSERT(rdrand(buf, sizeof(buf)));
    TEST_ASSERT(!memcmp(buf, expected1, sizeof(buf)));

    if (supportsRdSeed()) {
        counter = 0x0100000000000000llu;
        TEST_ASSERT(rdseed(buf, sizeof(buf)));
        TEST_ASSERT(!memcmp(buf, expected2, sizeof(buf)));
    }
}

void when_rng_dead_failure_returned() {
    static const uint8_t expected[32] = { 0 };
    static uint8_t buf[32];

    counter = 0;

    hook_rdrand = rng_failing_after;

    memset(buf, 1, sizeof(buf));

    TEST_ASSERT(!rdrand(buf, sizeof(buf)));
    TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));

    hook_rdseed = rng_failing_after;

    if (supportsRdSeed()) {
        memset(buf, 1, sizeof(buf));

        TEST_ASSERT(!rdseed(buf, sizeof(buf)));
        TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));
    }
}

void when_rng_fails_late_buffer_is_still_cleared() {
    static const uint8_t expected[17] = { 0 };
    static uint8_t buf[sizeof(expected)];

    // Run the test both at the second 64-bit word and the third partial word
    for (int i = 1; i < 3; i++) {
        hook_rdrand = rng_failing_after;
        hook_rdseed = NULL;

        memset(buf, 1, sizeof(buf));

        counter = i;
        TEST_ASSERT(!rdrand(buf, sizeof(buf)));
        TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));

        hook_rdseed = rng_failing_after;

        memset(buf, 1, sizeof(buf));

        if (supportsRdSeed()) {
            counter = i;
            TEST_ASSERT(!rdseed(buf, sizeof(buf)));
            TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));
        }
    }

}

void when_rdrand_broken_rdseed_works_eventually() {
    // Note: In this test we're relying on rdseed working independently of rdrand.
    // This normally works, but can fail on occasion, so we need a retry loop.
    // The main purpose is to verify that we're not (primarily) relying on rdrand for our
    // seed logic.

    if (!supportsRdSeed()) return;

    counter = 0;
    hook_rdrand = rng_failing_after;
    hook_rdseed = NULL;

    bool ok = false;
    static const uint8_t zeros[32] = {0};
    static uint8_t buf[sizeof(zeros)];
    for (int retry = 0; retry < 10000; retry++) {
        bool success = rdseed(buf, sizeof(buf));

        if (success) {
            TEST_ASSERT(memcmp(buf, zeros, sizeof(buf)));
            ok = true;
            break;
        } else {
            TEST_ASSERT(!memcmp(buf, zeros, sizeof(buf)));
        }
    }

    TEST_ASSERT(ok);
}

bool rng_broken(uint64_t *) {
    return false;
}

bool rng_counter(uint64_t *out) {
    *out = counter++;
    return true;
}

void when_rdseed_broken_rdrand_reduction_used() {
    counter = 0;
    hook_rdrand = rng_counter;
    hook_rdseed = rng_broken;

// These test vectors were generated manually as follows:
// perl -e 'for my $i (4..(1024+3)) { print pack "Q<", $i }'|
// openssl enc -K 00000000''00000000''01000000''00000000
//   -iv 02000000''00000000''03000000''00000000 -e
//   -in /dev/stdin -out /dev/stdout -aes-128-cbc -nopad|hexdump -C|tail
//
// (Note: '\' line continuations are not permitted in C comments.
//  Place them in the appropriate locations in the command above to
//  reproduce these values).

// Then the last block (line) was folded using:
// perl -e '@l = split " ", <>; for my $i (0..7) { printf q/%02x /, hex($l[$i]) ^ hex($l[$i+8]); } print "\n"'

    static const uint8_t expected[8] = {
        0x12, 0x25, 0xc9, 0x9e, 0x6b, 0xc4, 0x84, 0xb8
    };

    static uint8_t buf[sizeof(expected)];

    TEST_ASSERT(rdseed(buf, sizeof(buf)));

    TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));
}

void when_rdrand_stuck_failure_returned() {
    static const uint8_t expected[32] = { 0 };
    static uint8_t buf[32];

    hook_rdrand = rng_stuck_zero;

    memset(buf, 1, sizeof(buf));

    TEST_ASSERT(!rdrand(buf, sizeof(buf)));
    TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));

    memset(buf, 1, sizeof(buf));

    hook_rdrand = rng_stuck_ff;

    TEST_ASSERT(!rdrand(buf, sizeof(buf)));
    TEST_ASSERT(!memcmp(expected, buf, sizeof(buf)));
}

} // anon namespace

#define RUN_RD_RAND_TEST(name) do { \
    hook_rdrand = hook_rdseed = NULL; \
    RUNTEST(name); \
} while (0)

int main() {
    BEGIN_TEST();

    RUN_RD_RAND_TEST(when_rng_flaky_retry_works);
    RUN_RD_RAND_TEST(when_rng_dead_failure_returned);
    RUN_RD_RAND_TEST(when_rng_fails_late_buffer_is_still_cleared);
    RUN_RD_RAND_TEST(when_rdrand_broken_rdseed_works_eventually);
    RUN_RD_RAND_TEST(when_rdseed_broken_rdrand_reduction_used);
    RUN_RD_RAND_TEST(when_rdrand_stuck_failure_returned);

    END_TEST();
}

