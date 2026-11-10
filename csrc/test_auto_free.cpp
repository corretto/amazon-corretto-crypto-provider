// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "test_utils.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

using namespace AmazonCorrettoCryptoProvider;

namespace {

struct WatchedFree {
    void* ptr;
    int count;
};

WatchedFree watched[2] = { };

void* test_malloc(size_t size, const char*, int) { return std::malloc(size); }
void* test_realloc(void* ptr, size_t size, const char*, int) { return std::realloc(ptr, size); }
void test_free(void* ptr, const char*, int)
{
    for (auto& entry : watched) {
        if (ptr != nullptr && ptr == entry.ptr) {
            ++entry.count;
        }
    }
    std::free(ptr);
}

EVP_HPKE_KEY* new_watched_key(size_t index)
{
    EVP_HPKE_KEY* key = EVP_HPKE_KEY_new();
    TEST_ASSERT(key != nullptr);
    watched[index] = { key, 0 };
    return key;
}

void test_move_construction()
{
    EVP_HPKE_KEY* key = new_watched_key(0);
    {
        EVP_HPKE_KEY_auto source = EVP_HPKE_KEY_auto::from(key);
        // Nonzero storage makes an uninitialized destination pointer fail deterministically.
        alignas(EVP_HPKE_KEY_auto) unsigned char storage[sizeof(EVP_HPKE_KEY_auto)];
        memset(storage, 0xa5, sizeof(storage));
        auto* destination = new (storage) EVP_HPKE_KEY_auto(std::move(source));
        TEST_ASSERT(source.get() == nullptr && destination->get() == key);
        TEST_ASSERT(watched[0].count == 0);
        destination->~EVP_HPKE_KEY_auto();
        TEST_ASSERT(watched[0].count == 1);
    }
    TEST_ASSERT(watched[0].count == 1);
    watched[0] = { };

    EVP_HPKE_KEY_auto empty;
    EVP_HPKE_KEY_auto moved(std::move(empty));
    TEST_ASSERT(empty.get() == nullptr && moved.get() == nullptr);
}

void test_move_assignment_and_replacement()
{
    EVP_HPKE_KEY* first = new_watched_key(0);
    EVP_HPKE_KEY* second = new_watched_key(1);
    {
        EVP_HPKE_KEY_auto destination = EVP_HPKE_KEY_auto::from(first);
        EVP_HPKE_KEY_auto source = EVP_HPKE_KEY_auto::from(second);
        destination = std::move(source);
        TEST_ASSERT(source.get() == nullptr && destination.get() == second);
        TEST_ASSERT(watched[0].count == 1 && watched[1].count == 0);
        TEST_ASSERT(!destination.set(nullptr));
        TEST_ASSERT(destination.get() == nullptr && watched[1].count == 1);
        destination.clear();
    }
    TEST_ASSERT(watched[0].count == 1 && watched[1].count == 1);
    watched[0] = { };
    watched[1] = { };
}

void test_transfer_to_java_owner()
{
    EVP_HPKE_KEY* key = new_watched_key(0);
    jlong java_owner;
    {
        EVP_HPKE_KEY_auto native_owner = EVP_HPKE_KEY_auto::from(key);
        java_owner = reinterpret_cast<jlong>(native_owner.take());
        TEST_ASSERT(native_owner.get() == nullptr && watched[0].count == 0);
    }
    TEST_ASSERT(watched[0].count == 0);
    Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeRelease(nullptr, nullptr, java_owner);
    TEST_ASSERT(watched[0].count == 1);
    watched[0] = { };

    key = new_watched_key(0);
    {
        EVP_HPKE_KEY_auto native_owner = EVP_HPKE_KEY_auto::from(key);
        native_owner.releaseOwnership();
        TEST_ASSERT(native_owner.get() == nullptr);
    }
    TEST_ASSERT(watched[0].count == 0);
    EVP_HPKE_KEY_free(key);
    TEST_ASSERT(watched[0].count == 1);
    watched[0] = { };
}

} // namespace

int main()
{
    BEGIN_TEST();
    if (CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free) != 1) {
        std::fprintf(stderr, "Unable to install allocation tracking hooks\n");
        return 1;
    }
    RUNTEST(test_move_construction);
    RUNTEST(test_move_assignment_and_replacement);
    RUNTEST(test_transfer_to_java_owner);
    END_TEST();
}
