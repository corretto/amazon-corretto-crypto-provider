// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <functional>
#include <jni.h>

std::function<void(char const*)> call_fips_callback = [](char const*) { };

// To have this symbol exported, one needs to modify the final-link.version and the CMakeLists.txt
extern "C" void AWS_LC_fips_failure_callback(char const* message);

void AWS_LC_fips_failure_callback(char const* message)
{

    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    call_fips_callback(message);
}

extern "C" JNIEXPORT void JNICALL
Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_registerFipsStatusCallback(
    JNIEnv* env, jobject thisObj)
{
    // scope in |env| pointer and a reference to |thisObj|
    call_fips_callback = [env, &thisObj](char const* message) {
        jclass thisClass = env->GetObjectClass(thisObj);
        jmethodID mid = env->GetMethodID(thisClass, "addFipsStatusError", "(S)V");
        env->CallVoidMethod(thisObj, mid, message);
    };
}
// The following methods are for testing purposes
extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_resetFipsStatus(
    JNIEnv* env, jobject thisObj)
{
    jclass thisClass = env->GetObjectClass(thisObj);
    jmethodID mid = env->GetMethodID(thisClass, "clearFipsStatusErrors", "(V)V");
    env->CallVoidMethod(thisObj, mid);
}

extern "C" JNIEXPORT void JNICALL
Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_callAwsLcFipsFailureCallback(JNIEnv*, jclass)
{
    AWS_LC_fips_failure_callback("called by a test");
}
