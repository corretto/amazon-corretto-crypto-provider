// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef TEST_UTILS_H
#define TEST_UTILS_H 1

#include <openssl/err.h>

bool test_succeeded = true;
bool success = true;

#define BEGIN_TEST() \
  do { \
    success = true; \
  } while(0)

#define END_TEST() \
do { \
    bool errorFound = false; \
    const char* file; \
    int line; \
    unsigned long unhandledError = ERR_get_error_line(&file, &line); \
    while (unhandledError) { \
        errorFound = true; \
        std::cerr << "Found unhandled openssl error: " << formatOpensslError(unhandledError, "NO_TEXT"); \
        std::cerr << " @ " << file << ":" << line << std::endl; \
        unhandledError = ERR_get_error_line(&file, &line); \
    } \
    if (errorFound) { \
        FAIL(); \
    } \
    return success ? 0 : 1; \
  } while(0)

#define RUNTEST(name) do { \
    printf("Running test %s... ", #name); \
    test_succeeded = true; \
    name(); \
    if (test_succeeded) { \
        printf("ok\n"); \
    } else {\
        printf("FAILED test %s\n", #name); \
        success = false; \
    } \
} while (0)

#define TEST_ASSERT(x) do { \
    if (!(x)) { \
        test_succeeded = false; \
        printf("Failed assertion at %s:%d: %s\n", __FILE__, __LINE__, #x); \
    } \
} while (0)

#define FAIL() do { \
    test_succeeded = false; \
    success = false; \
    printf("Failed assertion at %s:%d\n", __FILE__, __LINE__); \
} while (0)

#endif //TEST_UTILS_H
