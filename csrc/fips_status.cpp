// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <functional>
#include <jni.h>

#include "string_vector.h"

static AmazonCorrettoCryptoProvider::ConcurrentStringVector fipsStatusErrors;

// To have this symbol exported, one needs to modify the final-link.version and the CMakeLists.txt
extern "C" void AWS_LC_fips_failure_callback(char const* message);

#if defined(FIPS_SELF_TEST_SKIP_ABORT)
void AWS_LC_fips_failure_callback(char const* message)
{
    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    fipsStatusErrors.push_back(message);
}
#else
void AWS_LC_fips_failure_callback(char const* message) { abort(); }
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

extern "C" JNIEXPORT int JNICALL
Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_fipsStatusErrorCount(JNIEnv* env, jobject thisObj)
{
    return fipsStatusErrors.size();
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
