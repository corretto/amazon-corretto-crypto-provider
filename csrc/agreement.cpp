// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include "generated-headers.h"
#include "env.h"
#include "buffer.h"
#include "util.h"
#include "keyutils.h"

using namespace AmazonCorrettoCryptoProvider;

namespace {

// Checks the openssl return value (and errorCode if needed)
// for various key-agreement methods and throws an appropriate
// C++-exception if necessary.
void checkAgreementResult(int result) {
    if (result > 0) {
        return;
    }
    unsigned long errCode = drainOpensslErrors();
    std::string msg = formatOpensslError(errCode, "Unexpectected agreement error");

    if (errCode == 0x05066066 // Invalid public key
        || errCode == 0x0609B099 // Different Parameters
        ) {
        throw_java_ex(EX_INVALID_KEY, msg);
    } else {
        throw_java_ex(EX_RUNTIME_CRYPTO, msg);
    }
}

}

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyAgreement_agree
(JNIEnv *pEnv,
 jclass clazz,
 jbyteArray privDerArr,
 jbyteArray pubDerArr,
 jint keyType,
 jboolean checkPrivateKey
) {
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);
        
        EvpKeyContext privCtx;
        EvpKeyContext pubCtx;
        {
            java_buffer privBuf = java_buffer::from_array(env, privDerArr);
            jni_borrow privDer(env, privBuf, "privDer");
            privCtx.setKey(der2EvpPrivateKey(privDer.data(), privDer.len(), checkPrivateKey, EX_INVALID_KEY));
            if (EVP_PKEY_base_id(privCtx.getKey()) != keyType) {
                throw_java_ex(EX_INVALID_KEY, "Unexpected key type for algorithm");
            }
        }
        {
            java_buffer pubBuf = java_buffer::from_array(env, pubDerArr);
            jni_borrow pubDer(env, pubBuf, "pubDer");
            pubCtx.setKey(der2EvpPublicKey(pubDer.data(), pubDer.len(), EX_INVALID_KEY));
            if (EVP_PKEY_base_id(pubCtx.getKey()) != keyType) {
                throw_java_ex(EX_INVALID_KEY, "Unexpected key type for algorithm");
            }
        }

        EVP_PKEY_CTX* pctx = privCtx.setKeyCtx(EVP_PKEY_CTX_new(privCtx.getKey(), NULL));
        if (!pctx) {
            throw_openssl("Unable to create PKEY_CTX");
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            throw_openssl("Unable to initialize context");
        }
        checkAgreementResult(EVP_PKEY_derive_set_peer(pctx, pubCtx.getKey()));
        
        size_t resultLen = 0;
        std::vector<uint8_t> tmpResult;

        checkAgreementResult(EVP_PKEY_derive(pctx, NULL, &resultLen));
        tmpResult.resize(resultLen);

        size_t returnedLen = resultLen;
        checkAgreementResult(EVP_PKEY_derive(pctx, &tmpResult[0], &returnedLen));

        // OpenSSL may trim leading zeros (which is incorrect, so we left-pad it)
        result = env->NewByteArray(resultLen);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate signature array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, resultLen - returnedLen, returnedLen, (jbyte*) &tmpResult[0]);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}

