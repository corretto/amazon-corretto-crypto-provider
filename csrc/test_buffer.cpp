// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "test_utils.h"
#include "util.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

struct FakeArray : _jbyteArray {
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> copy;
    uint8_t empty_byte = 0x42;
    bool copied;
    bool fail = false;
    bool cleansed = false;
    jint release_mode = -1;

    explicit FakeArray(size_t len, bool copied = false)
        : bytes(len, 0x42)
        , copied(copied)
    {
    }
};

struct FakeJni : JNIEnv {
    JNINativeInterface_ table = { };
    std::vector<std::unique_ptr<FakeArray> > arrays;
    std::vector<jarray> releases;
    std::vector<jarray> commits;
    std::vector<jarray> acquired;
    int active = 0;
    int acquisitions = 0;
    int new_arrays = 0;
    int reads = 0;
    int writes = 0;
    bool fail_new = false;
    _jclass exception_class;
    std::string exception_name;
    bool exception_pending = false;

    FakeJni()
    {
        functions = &table;
        releases.reserve(8);
        commits.reserve(8);
        acquired.reserve(8);
        table.IsSameObject = [](JNIEnv* env, jobject first, jobject second) -> jboolean {
            TEST_ASSERT(state(env).active == 0);
            return first == second ? JNI_TRUE : JNI_FALSE;
        };
        table.GetArrayLength = [](JNIEnv* env, jarray array) -> jsize {
            TEST_ASSERT(state(env).active == 0);
            return static_cast<jsize>(static_cast<FakeArray*>(array)->bytes.size());
        };
        table.NewByteArray = [](JNIEnv* env, jsize len) -> jbyteArray {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.new_arrays;
            if (jni.fail_new) {
                return nullptr;
            }
            jni.arrays.emplace_back(new FakeArray(static_cast<size_t>(len)));
            std::fill(jni.arrays.back()->bytes.begin(), jni.arrays.back()->bytes.end(), 0);
            return jni.arrays.back().get();
        };
        table.GetByteArrayRegion = [](JNIEnv* env, jbyteArray array, jsize off, jsize len, jbyte* dst) {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.reads;
            memcpy(dst, static_cast<FakeArray*>(array)->bytes.data() + off, static_cast<size_t>(len));
        };
        table.SetByteArrayRegion = [](JNIEnv* env, jbyteArray array, jsize off, jsize len, const jbyte* src) {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            ++jni.writes;
            jni.commits.push_back(array);
            memcpy(static_cast<FakeArray*>(array)->bytes.data() + off, src, static_cast<size_t>(len));
        };
        table.ExceptionCheck = [](JNIEnv* env) -> jboolean {
            TEST_ASSERT(state(env).active == 0);
            return state(env).exception_pending ? JNI_TRUE : JNI_FALSE;
        };
        table.FindClass = [](JNIEnv* env, const char* name) -> jclass {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0);
            jni.exception_name = name;
            return &jni.exception_class;
        };
        table.ThrowNew = [](JNIEnv* env, jclass clazz, const char*) -> jint {
            FakeJni& jni = state(env);
            TEST_ASSERT(jni.active == 0 && clazz == &jni.exception_class);
            jni.exception_pending = true;
            return 0;
        };
        table.GetPrimitiveArrayCritical = [](JNIEnv* env, jarray array, jboolean* copied) -> void* {
            FakeJni& jni = state(env);
            FakeArray& a = *static_cast<FakeArray*>(array);
            ++jni.acquisitions;
            jni.acquired.push_back(array);
            if (a.fail) {
                return nullptr;
            }
            ++jni.active;
            *copied = a.copied ? JNI_TRUE : JNI_FALSE;
            if (a.bytes.empty()) {
                return &a.empty_byte;
            }
            if (a.copied) {
                a.copy = a.bytes;
                return a.copy.data();
            }
            return a.bytes.data();
        };
        table.ReleasePrimitiveArrayCritical = [](JNIEnv* env, jarray array, void* ptr, jint mode) {
            FakeJni& jni = state(env);
            FakeArray& a = *static_cast<FakeArray*>(array);
            TEST_ASSERT(jni.active > 0);
            TEST_ASSERT(ptr == (a.bytes.empty() ? &a.empty_byte : (a.copied ? a.copy.data() : a.bytes.data())));
            --jni.active;
            jni.releases.push_back(array);
            a.release_mode = mode;
            if (a.copied) {
                a.cleansed = std::all_of(a.copy.begin(), a.copy.end(), [](uint8_t b) { return b == 0; });
                if (mode == 0) {
                    a.bytes = a.copy;
                }
                a.copy.clear();
            }
        };
    }

    static FakeJni& state(JNIEnv* env) { return *static_cast<FakeJni*>(env); }
};

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

struct TestHpkeSuite {
    const EVP_HPKE_KEM* (*kem)();
    const EVP_HPKE_KDF* (*kdf)();
    const EVP_HPKE_AEAD* (*aead)();
};

const TestHpkeSuite kTestHpkeSuites[] = {
#if defined(EVP_HPKE_MLKEM768)
    { EVP_hpke_mlkem768, EVP_hpke_hkdf_sha256, EVP_hpke_aes_128_gcm },
#endif
#if defined(EVP_HPKE_MLKEM1024) && defined(EVP_HPKE_HKDF_SHA384)
    { EVP_hpke_mlkem1024, EVP_hpke_hkdf_sha384, EVP_hpke_aes_256_gcm },
#endif
    { nullptr, nullptr, nullptr },
};

struct TestHpkeContexts {
    EVP_HPKE_CTX sender;
    EVP_HPKE_CTX recipient;
    bool ready;

    explicit TestHpkeContexts(const TestHpkeSuite& suite)
        : ready(false)
    {
        EVP_HPKE_CTX_zero(&sender);
        EVP_HPKE_CTX_zero(&recipient);
        EVP_HPKE_KEY_auto key = EVP_HPKE_KEY_auto::from(EVP_HPKE_KEY_new());
        uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
        uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
        size_t public_len = 0, enc_len = 0;
        ready = key.isInitialized() && EVP_HPKE_KEY_generate(key, suite.kem())
            && EVP_HPKE_KEY_public_key(key, public_key, &public_len, sizeof(public_key))
            && EVP_HPKE_CTX_setup_sender(&sender, enc, &enc_len, sizeof(enc), suite.kem(), suite.kdf(), suite.aead(),
                public_key, public_len, nullptr, 0)
            && EVP_HPKE_CTX_setup_recipient(&recipient, key, suite.kdf(), suite.aead(), enc, enc_len, nullptr, 0);
        TEST_ASSERT(ready);
    }

    ~TestHpkeContexts()
    {
        EVP_HPKE_CTX_cleanup(&recipient);
        EVP_HPKE_CTX_cleanup(&sender);
    }
};

void check_hpke_borrows(FakeJni& jni,
    FakeArray& output,
    FakeArray& input,
    FakeArray& aad,
    bool shared,
    bool seal,
    size_t input_len,
    size_t output_len,
    size_t aad_len)
{
    std::vector<jarray> expected;
    if (shared || output_len != 0) {
        expected.push_back(&output);
    }
    if (!shared && input_len != 0) {
        expected.push_back(&input);
    }
    if (aad_len != 0) {
        expected.push_back(&aad);
    }
    TEST_ASSERT(jni.acquired == expected && jni.acquisitions == static_cast<int>(expected.size()));
    std::reverse(expected.begin(), expected.end());
    TEST_ASSERT(jni.releases == expected && jni.active == 0 && !jni.exception_pending);
    const bool commits = output.copied && (shared || (!seal && output_len != 0));
    TEST_ASSERT(output.cleansed == commits);
    TEST_ASSERT(jni.writes == (commits ? 1 : 0));
    TEST_ASSERT(jni.commits == (commits ? std::vector<jarray>({ &output }) : std::vector<jarray>()));
    if (!shared) {
        TEST_ASSERT(input.cleansed == (input.copied && seal && input_len != 0));
    }
    TEST_ASSERT(!aad.cleansed);
}

void test_hpke_array_scopes()
{
    for (const auto& suite : kTestHpkeSuites) {
        if (!suite.kem) {
            break;
        }
        TestHpkeContexts contexts(suite);
        if (!contexts.ready) {
            return;
        }
        for (bool copied : { false, true }) {
            // Separate arrays, shared matching starts, and shared disjoint ranges.
            for (int layout : { 0, 1, 2 }) {
                const bool shared = layout != 0;
                for (size_t plain_len : { size_t(0), size_t(7) }) {
                    for (size_t offset : { size_t(0), size_t(3) }) {
                        for (size_t aad_len : { size_t(0), size_t(4) }) {
                            const size_t cipher_len = plain_len + EVP_HPKE_CTX_max_overhead(&contexts.sender);
                            const size_t input_offset = layout == 2 ? offset + cipher_len + 1 : offset;
                            FakeArray input(input_offset + plain_len, copied);
                            FakeArray ciphertext(
                                layout == 2 ? input_offset + plain_len + 2 : offset + cipher_len + 2, copied);
                            // An empty AAD range may also have a nonempty backing array.
                            FakeArray aad(offset == 0 ? aad_len : 4, copied);
                            const std::vector<uint8_t> plain(plain_len, 0x23);
                            FakeArray& seal_input = shared ? ciphertext : input;
                            std::copy(plain.begin(), plain.end(), seal_input.bytes.begin() + input_offset);
                            const auto input_before = input.bytes;
                            const auto cipher_before = ciphertext.bytes;
                            FakeJni seal_jni;
                            const jint sealed = Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeSeal(
                                &seal_jni, nullptr, reinterpret_cast<jlong>(&contexts.sender), &aad, aad_len,
                                &seal_input, input_offset, plain_len, &ciphertext, offset);
                            TEST_ASSERT(sealed == static_cast<jint>(cipher_len));
                            check_hpke_borrows(
                                seal_jni, ciphertext, seal_input, aad, shared, true, plain_len, cipher_len, aad_len);
                            TEST_ASSERT(input.bytes == input_before);
                            for (size_t i = 0; i < ciphertext.bytes.size(); ++i) {
                                if (i < offset || i >= offset + cipher_len) {
                                    TEST_ASSERT(ciphertext.bytes[i] == cipher_before[i]);
                                }
                            }

                            const size_t output_offset = layout == 2 ? input_offset : offset;
                            FakeArray output(output_offset + plain_len, copied);
                            FakeArray& open_output = shared ? ciphertext : output;
                            const auto open_before = open_output.bytes;
                            const auto cipher_sealed = ciphertext.bytes;
                            ciphertext.cleansed = false;
                            FakeJni open_jni;
                            const jint opened = Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeOpen(
                                &open_jni, nullptr, reinterpret_cast<jlong>(&contexts.recipient), &aad, aad_len,
                                &ciphertext, offset, cipher_len, &open_output, output_offset);
                            TEST_ASSERT(opened == static_cast<jint>(plain_len));
                            check_hpke_borrows(
                                open_jni, open_output, ciphertext, aad, shared, false, cipher_len, plain_len, aad_len);
                            TEST_ASSERT(
                                std::equal(plain.begin(), plain.end(), open_output.bytes.begin() + output_offset));
                            for (size_t i = 0; i < open_output.bytes.size(); ++i) {
                                if (i < output_offset || i >= output_offset + plain_len) {
                                    TEST_ASSERT(open_output.bytes[i] == open_before[i]);
                                }
                            }
                            if (!shared) {
                                TEST_ASSERT(ciphertext.bytes == cipher_sealed);
                            }
                        }
                    }
                }
            }
        }
    }
}

void test_hpke_acquisition_failure()
{
    for (const auto& suite : kTestHpkeSuites) {
        if (!suite.kem) {
            break;
        }
        TestHpkeContexts contexts(suite);
        if (!contexts.ready) {
            return;
        }
        for (bool copied : { false, true }) {
            for (bool shared : { false, true }) {
                for (bool seal : { false, true }) {
                    // Fail at each possible acquisition, including AAD after input.
                    for (int failure = 0; failure < (shared ? 2 : 3); ++failure) {
                        FakeJni jni;
                        FakeArray output(32, copied), input(32, copied), aad(4, copied);
                        FakeArray& source = shared ? output : input;
                        std::vector<FakeArray*> order = { &output };
                        if (!shared) {
                            order.push_back(&input);
                        }
                        order.push_back(&aad);
                        order[failure]->fail = true;
                        const auto output_before = output.bytes;
                        const auto input_before = input.bytes;
                        const jlong ctx = reinterpret_cast<jlong>(seal ? &contexts.sender : &contexts.recipient);
                        const jint written = seal ? Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeSeal(
                                                        &jni, nullptr, ctx, &aad, 4, &source, 0, 7, &output, 0)
                                                  : Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeOpen(
                                                        &jni, nullptr, ctx, &aad, 4, &source, 0, 23, &output, 0);
                        TEST_ASSERT(written == 0 && jni.exception_pending && jni.exception_name == EX_ERROR);
                        TEST_ASSERT(jni.acquisitions == failure + 1 && jni.active == 0);
                        std::vector<jarray> acquired(order.begin(), order.begin() + failure + 1);
                        std::vector<jarray> released(order.begin(), order.begin() + failure);
                        std::reverse(released.begin(), released.end());
                        TEST_ASSERT(jni.acquired == acquired && jni.releases == released);
                        const bool commits = copied && failure > 0 && (shared || !seal);
                        TEST_ASSERT(jni.writes == (commits ? 1 : 0) && output.cleansed == commits);
                        TEST_ASSERT(
                            jni.commits == (commits ? std::vector<jarray>({ &output }) : std::vector<jarray>()));
                        TEST_ASSERT(input.cleansed == (copied && !shared && seal && failure == 2));
                        TEST_ASSERT(output.bytes == output_before && input.bytes == input_before && !aad.cleansed);
                    }
                }
            }
        }
    }
}

void test_hpke_seed_conversion()
{
    const jint suites[][3] = {
#if defined(EVP_HPKE_MLKEM768)
        { EVP_HPKE_MLKEM768, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM },
#endif
#if defined(EVP_HPKE_MLKEM1024) && defined(EVP_HPKE_HKDF_SHA384)
        { EVP_HPKE_MLKEM1024, EVP_HPKE_HKDF_SHA384, EVP_HPKE_AES_256_GCM },
#endif
        { 0, 0, 0 },
    };
    for (const auto& suite : suites) {
        if (suite[0] == 0) {
            break;
        }
        for (size_t len : { size_t(0), size_t(63), size_t(65), size_t(2400) }) {
            FakeJni jni;
            FakeArray seed(len);
            const jlong key = Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeImport(
                &jni, nullptr, suite[0], suite[1], suite[2], &seed);
            TEST_ASSERT(key == 0 && jni.exception_pending && jni.exception_name == EX_INVALID_KEY);
            TEST_ASSERT(jni.reads == 0);
        }

        FakeJni jni;
        FakeArray seed(64);
        for (size_t i = 0; i < seed.bytes.size(); ++i) {
            seed.bytes[i] = static_cast<uint8_t>(i);
        }
        const jlong key_ptr = Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeImport(
            &jni, nullptr, suite[0], suite[1], suite[2], &seed);
        EVP_HPKE_KEY_auto key = EVP_HPKE_KEY_auto::from(reinterpret_cast<EVP_HPKE_KEY*>(key_ptr));
        TEST_ASSERT(!jni.exception_pending && key.isInitialized());
        if (!key.isInitialized()) {
            return;
        }
        jbyteArray encoded
            = Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeGetPrivateKey(&jni, nullptr, key_ptr);
        TEST_ASSERT(encoded != nullptr && !jni.exception_pending);
        if (encoded != nullptr) {
            TEST_ASSERT(static_cast<FakeArray*>(encoded)->bytes == seed.bytes);
        }
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
    RUNTEST(test_hpke_array_scopes);
    RUNTEST(test_hpke_acquisition_failure);
    RUNTEST(test_hpke_seed_conversion);
    RUNTEST(test_cleanse_and_stash_copies_then_zeros_source);
    RUNTEST(test_cleanse_and_stash_zero_length_is_noop);
    RUNTEST(test_cleanse_and_stash_overwrites_existing_stash);
    END_TEST();
}
