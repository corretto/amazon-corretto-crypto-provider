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

EVP_PKEY* new_watched_key(size_t index)
{
    EVP_PKEY* key = EVP_PKEY_new();
    TEST_ASSERT(key != nullptr);
    watched[index] = { key, 0 };
    return key;
}

void test_move_construction()
{
    EVP_PKEY* key = new_watched_key(0);
    {
        EVP_PKEY_auto source = EVP_PKEY_auto::from(key);
        // Nonzero storage makes an uninitialized destination pointer fail deterministically.
        alignas(EVP_PKEY_auto) unsigned char storage[sizeof(EVP_PKEY_auto)];
        memset(storage, 0xa5, sizeof(storage));
        auto* destination = new (storage) EVP_PKEY_auto(std::move(source));
        TEST_ASSERT(source.get() == nullptr && destination->get() == key);
        TEST_ASSERT(watched[0].count == 0);
        destination->~EVP_PKEY_auto();
        TEST_ASSERT(watched[0].count == 1);
    }
    TEST_ASSERT(watched[0].count == 1);
    watched[0] = { };

    EVP_PKEY_auto empty;
    EVP_PKEY_auto moved(std::move(empty));
    TEST_ASSERT(empty.get() == nullptr && moved.get() == nullptr);
}

void test_move_assignment_and_replacement()
{
    EVP_PKEY* first = new_watched_key(0);
    EVP_PKEY* second = new_watched_key(1);
    {
        EVP_PKEY_auto destination = EVP_PKEY_auto::from(first);
        EVP_PKEY_auto source = EVP_PKEY_auto::from(second);
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

void test_release_ownership()
{
    EVP_PKEY* key = new_watched_key(0);
    {
        EVP_PKEY_auto owner = EVP_PKEY_auto::from(key);
        TEST_ASSERT(owner.take() == key && owner.get() == nullptr);
    }
    TEST_ASSERT(watched[0].count == 0);
    EVP_PKEY_free(key);
    TEST_ASSERT(watched[0].count == 1);
    watched[0] = { };

    key = new_watched_key(0);
    {
        EVP_PKEY_auto owner = EVP_PKEY_auto::from(key);
        owner.releaseOwnership();
        TEST_ASSERT(owner.get() == nullptr);
    }
    TEST_ASSERT(watched[0].count == 0);
    EVP_PKEY_free(key);
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
    RUNTEST(test_release_ownership);
    END_TEST();
}
