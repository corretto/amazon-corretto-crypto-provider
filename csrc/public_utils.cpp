// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <cstdlib>

#include "auto_free.h"
#include "env.h"

namespace AmazonCorrettoCryptoProvider {

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    computeMLDSAMuInternal
 * Signature: ([B[B)[B
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_PublicUtils_computeMLDSAMuInternal(
    JNIEnv* pEnv, jclass, jbyteArray pubKeyEncodedArr, jbyteArray messageArr)
{
    try {
        raii_env env(pEnv);
        jsize pub_key_der_len = env->GetArrayLength(pubKeyEncodedArr);
        jsize message_len = env->GetArrayLength(messageArr);
        uint8_t* pub_key_der = (uint8_t*)env->GetByteArrayElements(pubKeyEncodedArr, nullptr);
        CHECK_OPENSSL(pub_key_der);
        uint8_t* message = (uint8_t*)env->GetByteArrayElements(messageArr, nullptr);
        CHECK_OPENSSL(message);

        CBS cbs;
        CBS_init(&cbs, pub_key_der, pub_key_der_len);
        EVP_PKEY_auto pkey = EVP_PKEY_auto::from((EVP_parse_public_key(&cbs)));
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        EVP_MD_CTX_auto md_ctx_mu = EVP_MD_CTX_auto::from(EVP_MD_CTX_new());
        EVP_MD_CTX_auto md_ctx_pk = EVP_MD_CTX_auto::from(EVP_MD_CTX_new());

        size_t pk_len; // fetch the public key length
        CHECK_OPENSSL(EVP_PKEY_get_raw_public_key(pkey.get(), nullptr, &pk_len));
        std::vector<uint8_t> pk(pk_len);
        CHECK_OPENSSL(EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len));
        uint8_t tr[64] = { 0 };
        uint8_t mu[64] = { 0 };
        uint8_t pre[2] = { 0 };

        // get raw public key and hash it
        CHECK_OPENSSL(EVP_DigestInit_ex(md_ctx_pk.get(), EVP_shake256(), nullptr));
        CHECK_OPENSSL(EVP_DigestUpdate(md_ctx_pk.get(), pk.data(), pk_len));
        CHECK_OPENSSL(EVP_DigestFinalXOF(md_ctx_pk.get(), tr, sizeof(tr)));

        // compute mu
        CHECK_OPENSSL(EVP_DigestInit_ex(md_ctx_mu.get(), EVP_shake256(), nullptr));
        CHECK_OPENSSL(EVP_DigestUpdate(md_ctx_mu.get(), tr, sizeof(tr)));
        CHECK_OPENSSL(EVP_DigestUpdate(md_ctx_mu.get(), pre, sizeof(pre)));
        CHECK_OPENSSL(EVP_DigestUpdate(md_ctx_mu.get(), message, message_len));
        CHECK_OPENSSL(EVP_DigestFinalXOF(md_ctx_mu.get(), mu, sizeof(mu)));

        env->ReleaseByteArrayElements(pubKeyEncodedArr, (jbyte*)pub_key_der, 0);
        env->ReleaseByteArrayElements(messageArr, (jbyte*)message, 0);

        jbyteArray ret = env->NewByteArray(sizeof(mu));
        env->SetByteArrayRegion(ret, 0, sizeof(mu), (const jbyte*)mu);
        return ret;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

} // namespace
