// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "atomic_bool.h"

#include <jni.h>
#include <cstdio>

// To have this symbol exported, one needs to modify the final-link.version and the CMakeLists.txt
extern "C" void AWS_LC_fips_failure_callback(char const* message);

AmazonCorrettoCryptoProvider::AtomicBool g_is_fips_status_ok(true);

void AWS_LC_fips_failure_callback(char const* message) {
    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    g_is_fips_status_ok.store(false);
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_isFipsStatusOk(JNIEnv*, jobject) {
    return g_is_fips_status_ok.load() ? JNI_TRUE : JNI_FALSE;
}

// The following methods are for testing purposes
extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_flipFipsStatus(JNIEnv*, jclass) {
    g_is_fips_status_ok.store(!g_is_fips_status_ok.load());
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_callAwsLcFipsFailureCallback(JNIEnv*, jclass) {
    AWS_LC_fips_failure_callback("called by a test");
}
