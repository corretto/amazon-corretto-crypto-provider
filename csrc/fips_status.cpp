// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/crypto.h>
#include <cstdio>
#include <functional>
#include <jni.h>
#include <string.h>
#include <vector>

#include "string_vector.h"

static AmazonCorrettoCryptoProvider::ConcurrentStringVector fipsStatusErrors(1024);

// To have this symbol exported, one needs to modify the final-link.version and the CMakeLists.txt
extern "C" void AWS_LC_fips_failure_callback(char const* message);

#if defined(FIPS_SELF_TEST_SKIP_ABORT)
void AWS_LC_fips_failure_callback(char const* message)
{
    // Must track https://github.com/aws/aws-lc/blob/e4885d5e22f7dc482dd6bfa713b0e1b763b5c538/crypto/fipsmodule/self_check/self_check.c#L52
    const size_t char_limit = 10315;    // (2 * (2 * 2560)) + 42 + 33
    if (strnlen(message, char_limit + 1) > char_limit) {
        fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message message exceeding %lu chars\n", char_limit);
        return;
    }
    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    fipsStatusErrors.push_back(message);
}
#else
void AWS_LC_fips_failure_callback(char const* message)
{
    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    abort();
}
#endif

extern "C" JNIEXPORT jobject JNICALL
Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_getFipsSelfTestFailuresInternal(
    JNIEnv* env, jobject thisObj)
{
    std::vector<std::string> errors = fipsStatusErrors.to_std();

    // Construct a Java ArrayList, get a handle for the |add| method
    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    if (arrayListClass == NULL) {
        abort();
    }
    jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
    if (constructor == NULL) {
        abort();
    }
    jobject arrayList = env->NewObject(arrayListClass, constructor);
    if (arrayList == NULL) {
        abort();
    }
    jmethodID addMethod = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");
    if (addMethod == NULL) {
        abort();
    }

    // Copy the errors over to |arrayList| and clean up temporary local reference
    for (size_t i = 0; i < errors.size(); i++) {
        jstring javaString = env->NewStringUTF(errors[i].c_str());
        env->CallVoidMethod(arrayList, addMethod, javaString);
        env->DeleteLocalRef(javaString);
    }

    return arrayList;
}

extern "C" JNIEXPORT bool JNICALL
Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_isFipsStatusOkInternal(
    JNIEnv* env, jobject thisObj)
{
#if defined(EXPERIMENTAL_FIPS_BUILD)
    if (!FIPS_is_entropy_cpu_jitter()) {
        AWS_LC_fips_failure_callback("CPU Jitter is not enabled");
        return false;
    }
#else
    // Below macro check can be removed once we consume an AWS-LC-FIPS verison with |FIPS_is_entropy_cpu_jitter|.
    // Until then, this function should never be called unless we're in EXPERIMENTAL_FIPS_BUILD, so abort below
    // to alert us when EXPERIMENTAL_FIPS_BUILD is dropped from FIPS_SELF_TEST_SKIP_ABORT in testing.
    abort();
#endif
    return fipsStatusErrors.size() == 0;
}

// TEST methods below

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_resetFipsStatus(
    JNIEnv*, jclass)
{
    fipsStatusErrors.clear();
}

extern "C" JNIEXPORT void JNICALL
Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_callAwsLcFipsFailureCallback(JNIEnv*, jclass)
{
    AWS_LC_fips_failure_callback("called by a test");
}
