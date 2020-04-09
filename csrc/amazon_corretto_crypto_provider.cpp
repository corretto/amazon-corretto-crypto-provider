// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/crypto.h>
#include "generated-headers.h"
#include "util.h"
#include "rdrand.h"

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider
 * Method:    nativeRdRandSupported
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_nativeRdRandSupported
        (JNIEnv *, jclass) {
    return (supportsRdRand() ? JNI_TRUE : JNI_FALSE);
}
