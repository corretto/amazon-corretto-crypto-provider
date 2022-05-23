// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include "auto_free.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

// Checks the openssl return value (and errorCode if needed)
// for various key-agreement methods and throws an appropriate
// C++-exception if necessary.
void checkAgreementResult(int result)
{
    if (result > 0) {
        return;
    }
    unsigned long errCode = drainOpensslErrors();
    std::string msg = formatOpensslError(errCode, "Unexpectected agreement error");

    if (errCode == 0x05066065    // Invalid public key
        || errCode == 0x06000068 // Different Parameters
    ) {
        throw_java_ex(EX_INVALID_KEY, msg);
    } else {
        throw_java_ex(EX_RUNTIME_CRYPTO, msg);
    }
}
} // namespace

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyAgreement_agree(
    JNIEnv* pEnv, jclass clazz, jlong privateKeyPtr, jlong publicKeyPtr)
{
    jbyteArray result = NULL;

    EVP_PKEY* privKey = reinterpret_cast<EVP_PKEY*>(privateKeyPtr);
    EVP_PKEY* pubKey = reinterpret_cast<EVP_PKEY*>(publicKeyPtr);

    try {
        raii_env env(pEnv);

        EVP_PKEY_CTX_auto pctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(privKey, NULL));
        if (!pctx.isInitialized()) {
            throw_openssl("Unable to create PKEY_CTX");
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            throw_openssl("Unable to initialize context");
        }
        checkAgreementResult(EVP_PKEY_derive_set_peer(pctx, pubKey));

        size_t resultLen = 0;
        std::vector<uint8_t> tmpResult;

        checkAgreementResult(EVP_PKEY_derive(pctx, NULL, &resultLen));
        tmpResult.resize(resultLen);

        size_t returnedLen = resultLen;
        checkAgreementResult(EVP_PKEY_derive(pctx, &tmpResult[0], &returnedLen));

        // OpenSSL may trim leading zeros (which is incorrect, so we left-pad it)
        result = env->NewByteArray(resultLen);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate agreement array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, resultLen - returnedLen, returnedLen, (jbyte*)&tmpResult[0]);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}
