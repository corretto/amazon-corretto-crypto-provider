// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "generated-headers.h"
#include "test_fake_jni.h"
#include "test_utils.h"
#include "util.h"
#include <openssl/hpke.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

// Native tests for csrc/hpke.cpp: Java array borrows across seal/open, and key ownership.
namespace {

// Counts frees of one watched pointer, through AWS-LC's allocation hooks.
void* watched_ptr = nullptr;
int watched_frees = 0;

void* test_malloc(size_t size, const char*, int) { return std::malloc(size); }
void* test_realloc(void* ptr, size_t size, const char*, int) { return std::realloc(ptr, size); }
void test_free(void* ptr, const char*, int)
{
    if (ptr != nullptr && ptr == watched_ptr) {
        ++watched_frees;
    }
    std::free(ptr);
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

void test_private_key_native_release()
{
    EVP_HPKE_KEY* key = EVP_HPKE_KEY_new();
    TEST_ASSERT(key != nullptr);
    watched_ptr = key;
    watched_frees = 0;
    jlong java_owner;
    {
        EVP_HPKE_KEY_auto native_owner = EVP_HPKE_KEY_auto::from(key);
        java_owner = reinterpret_cast<jlong>(native_owner.take());
        TEST_ASSERT(native_owner.get() == nullptr);
    }
    TEST_ASSERT(watched_frees == 0);
    Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeRelease(nullptr, nullptr, java_owner);
    TEST_ASSERT(watched_frees == 1);
    watched_ptr = nullptr;
}

} // namespace

int main()
{
    BEGIN_TEST();
    if (CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free) != 1) {
        std::fprintf(stderr, "Unable to install allocation tracking hooks\n");
        return 1;
    }
    RUNTEST(test_hpke_array_scopes);
    RUNTEST(test_hpke_acquisition_failure);
    RUNTEST(test_hpke_seed_conversion);
    RUNTEST(test_private_key_native_release);
    END_TEST();
}
