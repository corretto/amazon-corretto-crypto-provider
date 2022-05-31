// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "generated-headers.h"
#include "compiler.h" // This is minimal so is safe to include
#include <dlfcn.h>
#include <stdlib.h>

#ifndef AWSLC_MANGLE
#define AWSLC_MANGLE
#endif

// The function in the symbol table we use to recognize that libcrypto has been loaded.
#define CANARY_FUNCTION_NAME STRINGIFY(AWSLC_MANGLE) "CRYPTO_library_init"

// We're purposefully taking no standard ACCP dependencies in this file
// so that it is minimal and stand alone.
namespace {
    void throw_java_exception(JNIEnv* env, const char* className, const char* message) {
        if (env->ExceptionCheck()) {
            // There already is a queued exception
            return;
        }
        jclass ex_class = env->FindClass(className);
        // If ex_class is null, then java implicitly threw a ClassDefNotFoundError
        if (ex_class != nullptr)
        {
            int rv = env->ThrowNew(ex_class, message);
            if (rv != 0) {
                env->FatalError("ThrowNew returned error");
                abort();
            }
        }
    }

    // Returns nullptr if the library is properly loaded.
    // Otherwise returns a string containing the error seen when trying to access CANARY_FUNCTION_NAME.
    // This string does *not* need to be freed.
    char* libraryLoadError() {
        dlerror();                                 // Clear errors
        dlsym(RTLD_DEFAULT, CANARY_FUNCTION_NAME); // Return value doesn't matter
        return dlerror();         // Did the lookup succeed?
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_loadLibCrypto(
    JNIEnv* pEnv, jclass, jstring libPath)
{
    // Have we already loaded a properly mangled version of AWS-LC?
    if (libraryLoadError() == nullptr) {
        // Already loaded
        return JNI_FALSE; // We didn't do anything
    }

    // We need to load it now
    if (libPath == nullptr) {
        throw_java_exception(pEnv, "java/lang/NullPointerException", "Library file was null");
        return JNI_FALSE;
    }
    const char* nativePath = pEnv->GetStringUTFChars(libPath, NULL);
    void* libPtr = dlopen(nativePath, RTLD_LAZY | RTLD_GLOBAL);
    // Immediately release the string regardless of if we were successful
    pEnv->ReleaseStringUTFChars(libPath, nativePath);

    if (libPtr == nullptr) {
        throw_java_exception(pEnv, "com/amazon/corretto/crypto/provider/RuntimeCryptoException", dlerror());
        return JNI_FALSE;
    }
    char* loadError = libraryLoadError();
    if (loadError != nullptr) {
        throw_java_exception(pEnv, "com/amazon/corretto/crypto/provider/RuntimeCryptoException", loadError);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}
