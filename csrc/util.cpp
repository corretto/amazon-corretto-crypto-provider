// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "generated-headers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stddef.h>
#include <string>

#include "env.h"
#include "util.h"

#define CLASSNOTFOUND_TYPE "java/lang/NoClassDefFoundError"

namespace AmazonCorrettoCryptoProvider {

unsigned long drainOpensslErrors()
{
    unsigned long result = 0;
    unsigned long tmp = ERR_get_error();
    while (tmp != 0) {
        result = tmp;
        tmp = ERR_get_error();
    }
    return result;
}

std::string formatOpensslError(unsigned long errCode, const char* fallback)
{
    if (errCode) {
        char buffer[256];
        ERR_error_string_n(errCode, buffer, sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0';
        return std::string(buffer);
    } else {
        return std::string(fallback);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_Utils_releaseEvpCipherCtx(
    JNIEnv*, jclass, jlong ctxPtr)
{
    EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr));
}

EVP_MD const* digest_code_to_EVP_MD(int digestCode)
{
    switch (digestCode) {
    case com_amazon_corretto_crypto_provider_Utils_SHA1_CODE:
        return EVP_sha1();
    case com_amazon_corretto_crypto_provider_Utils_SHA256_CODE:
        return EVP_sha256();
    case com_amazon_corretto_crypto_provider_Utils_SHA384_CODE:
        return EVP_sha384();
    case com_amazon_corretto_crypto_provider_Utils_SHA512_CODE:
        return EVP_sha512();
    default:
        throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE.");
    }
}

} // namespace
