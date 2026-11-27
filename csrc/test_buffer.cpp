// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "test_fake_jni.h"
#include "test_utils.h"
#include "util.h"
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

void test_array_conversions()
{
    FakeJni jni;
    raii_env env(&jni);
    std::vector<uint8_t, SecureAlloc<uint8_t> > empty;
    FakeArray empty_array(0);
    TEST_ASSERT(java_buffer::from_array(env, &empty_array).to_vector(env).empty());
    TEST_ASSERT(jni.reads == 0);
    TEST_ASSERT(static_cast<FakeArray*>(vecToArray(env, empty))->bytes.empty());
    TEST_ASSERT(static_cast<FakeArray*>(bytesToArray(env, nullptr, 0))->bytes.empty());
    TEST_ASSERT(jni.writes == 0);

    FakeArray array(4);
    array.bytes = { 1, 2, 3, 4 };
    auto slice = java_buffer::from_array(env, &array, 1, 2).to_vector(env);
    TEST_ASSERT(slice.size() == 2 && slice[0] == 2 && slice[1] == 3);
    TEST_ASSERT(static_cast<FakeArray*>(vecToArray(env, slice))->bytes == std::vector<uint8_t>({ 2, 3 }));
    TEST_ASSERT(static_cast<FakeArray*>(bytesToArray(env, array.bytes.data(), 4))->bytes == array.bytes);

    const int allocations = jni.new_arrays;
    try {
        bytesToArray(env, nullptr, static_cast<size_t>(std::numeric_limits<jsize>::max()) + 1);
        FAIL();
    } catch (java_ex& ex) {
        TEST_ASSERT(jni.new_arrays == allocations);
        ex.throw_to_java(&jni);
        TEST_ASSERT(jni.exception_pending && jni.exception_name == EX_OOM);
        jni.exception_pending = false;
    }
    jni.fail_new = true;
    try {
        bytesToArray(env, nullptr, 0);
        FAIL();
    } catch (java_ex& ex) {
        TEST_ASSERT(jni.writes == 2);
        ex.throw_to_java(&jni);
        TEST_ASSERT(jni.exception_pending && jni.exception_name == EX_OOM);
    }
}

void test_empty_borrows()
{
    for (bool copied : { false, true }) {
        for (WipeMode mode : { WipeMode::NO_WIPE, WipeMode::WIPE_INPUT, WipeMode::WIPE_OUTPUT }) {
            FakeJni jni;
            FakeArray array(0, copied);
            {
                JByteArrayCritical empty(&jni, &array, 0, mode);
                TEST_ASSERT(empty.get() != nullptr && jni.active == 1 && jni.acquisitions == 1);
                empty.release();
                empty.release();
                empty.commitBack();
                TEST_ASSERT(empty.get() == nullptr);
            }
            TEST_ASSERT(jni.active == 0 && jni.releases == std::vector<jarray>({ &array }));
            TEST_ASSERT(array.release_mode == (copied && mode != WipeMode::NO_WIPE ? JNI_ABORT : 0));
            TEST_ASSERT(array.bytes.empty() && array.empty_byte == 0x42 && jni.writes == 0);
        }
    }
}

void test_pinned_and_copied_borrows()
{
    for (bool copied : { false, true }) {
        for (WipeMode mode : { WipeMode::NO_WIPE, WipeMode::WIPE_INPUT, WipeMode::WIPE_OUTPUT }) {
            FakeJni jni;
            FakeArray array(4, copied);
            {
                JByteArrayCritical borrow(&jni, &array, 4, mode);
                TEST_ASSERT(jni.active == 1);
                if (mode != WipeMode::WIPE_INPUT) {
                    borrow.get()[1] = 0x99;
                }
            }
            const bool wiped = copied && mode != WipeMode::NO_WIPE;
            TEST_ASSERT(array.release_mode == (wiped ? JNI_ABORT : 0));
            TEST_ASSERT(array.cleansed == wiped);
            TEST_ASSERT(array.bytes[1] == (mode == WipeMode::WIPE_INPUT ? 0x42 : 0x99));
            TEST_ASSERT(array.bytes[0] == 0x42 && array.bytes[2] == 0x42 && array.bytes[3] == 0x42);
            TEST_ASSERT(jni.active == 0 && jni.releases.size() == 1);
            TEST_ASSERT(jni.writes == (copied && mode == WipeMode::WIPE_OUTPUT ? 1 : 0));
        }
    }
}

void test_release_before_commit_and_idempotence()
{
    FakeJni jni;
    FakeArray first(4, true), second(4, true), secret(4, true);
    {
        JByteArrayCritical out1(&jni, &first, 4, WipeMode::WIPE_OUTPUT);
        JByteArrayCritical out2(&jni, &second, 4, WipeMode::WIPE_OUTPUT);
        JByteArrayCritical input(&jni, &secret, 4, WipeMode::WIPE_INPUT);
        out1.get()[0] = 1;
        out2.get()[0] = 2;
        input.release();
        out2.release();
        out1.release();
        TEST_ASSERT(jni.active == 0 && jni.writes == 0);
        TEST_ASSERT(first.bytes[0] == 0x42 && second.bytes[0] == 0x42);
        TEST_ASSERT(first.cleansed && second.cleansed && secret.cleansed);
        out2.commitBack();
        out1.commitBack();
        TEST_ASSERT(first.bytes[0] == 1 && second.bytes[0] == 2 && secret.bytes[0] == 0x42);
        out1.release();
        out2.release();
        input.release();
        out1.commitBack();
        out2.commitBack();
        TEST_ASSERT(out1.get() == nullptr && out2.get() == nullptr && input.get() == nullptr);
    }
    TEST_ASSERT(jni.writes == 2 && jni.releases == std::vector<jarray>({ &secret, &second, &first }));
    TEST_ASSERT(jni.commits == std::vector<jarray>({ &second, &first }));
}

void test_unwind_after_acquisition_failure()
{
    FakeJni jni;
    FakeArray output(4, true), secret(4, true), failing(4, true);
    failing.fail = true;
    try {
        JByteArrayCritical out(&jni, &output, 4, WipeMode::WIPE_OUTPUT);
        JByteArrayCritical input(&jni, &secret, 4, WipeMode::WIPE_INPUT);
        out.get()[0] = 0x99;
        JByteArrayCritical failure(&jni, &failing, 4, WipeMode::NO_WIPE);
        FAIL();
    } catch (java_ex& ex) {
        TEST_ASSERT(jni.active == 0 && jni.acquisitions == 3 && jni.writes == 1);
        TEST_ASSERT(jni.releases == std::vector<jarray>({ &secret, &output }));
        TEST_ASSERT(output.cleansed && secret.cleansed);
        TEST_ASSERT(output.bytes[0] == 0x99 && secret.bytes[0] == 0x42);
        ex.throw_to_java(&jni);
        TEST_ASSERT(jni.exception_pending && jni.exception_name == EX_ERROR);
    }
}

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
    RUNTEST(test_array_conversions);
    RUNTEST(test_empty_borrows);
    RUNTEST(test_pinned_and_copied_borrows);
    RUNTEST(test_release_before_commit_and_idempotence);
    RUNTEST(test_unwind_after_acquisition_failure);
    RUNTEST(test_cleanse_and_stash_copies_then_zeros_source);
    RUNTEST(test_cleanse_and_stash_zero_length_is_noop);
    RUNTEST(test_cleanse_and_stash_overwrites_existing_stash);
    END_TEST();
}
