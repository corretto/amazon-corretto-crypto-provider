// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <dlfcn.h>
#include "generated-headers.h"
#include "env.h"

using namespace AmazonCorrettoCryptoProvider;

// The function in the symbol table we use to recognize that libcrypto has been loaded.
#define CANARY_FUNCTION_NAME STRINGIFY(AWSLC_MANGLE) "CRYPTO_library_init"

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_loadLibCrypto(
    JNIEnv* pEnv, jclass, jstring libPath)
{
    try {
        raii_env env(pEnv);

        // Have we already loaded a properly mangled version of AWS-LC?
        dlerror(); // Clear errors
        dlsym(RTLD_DEFAULT, CANARY_FUNCTION_NAME); // Return value doesn't matter
        char* dlErrorReturned = dlerror(); // Did the lookup succeed?
        if (dlErrorReturned == nullptr) {
            // Already loaded
            return JNI_FALSE; // We didn't do anything
        }

        // We need to load it now
        jni_string path(env, libPath);
        void* libPtr = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (libPtr == nullptr) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unable to load libcrypto");
        }
        dlerror(); // Clear errors
        dlErrorReturned = dlerror(); // Did the lookup succeed?
        if (dlErrorReturned == nullptr) {
            return JNI_TRUE; // No error
        } else {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Loaded library did not contain function: " CANARY_FUNCTION_NAME);
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return JNI_FALSE;
}
