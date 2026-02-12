// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_RsaEmsaPss_signEmsaPss(JNIEnv* pEnv,
    jclass,
    jlong pKey,
    jlong hashMd,
    jlong mgfMd,
    jint saltLen,
    jbyteArray digestArr,
    jint offset,
    jint length)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pKey);
        const EVP_MD* md = reinterpret_cast<const EVP_MD*>(hashMd);
        const EVP_MD* mgf_md = reinterpret_cast<const EVP_MD*>(mgfMd);

        if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Key must be RSA");
        }

        // Get RSA key from EVP_PKEY
        RSA* rsa = EVP_PKEY_get0_RSA(key);
        if (rsa == nullptr) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Failed to get RSA key");
        }

        // Get hash length
        size_t hLen = EVP_MD_size(md);

        // Validate digest length
        if ((size_t)length != hLen) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Digest length mismatch");
        }

        // Get digest bytes and copy them out of the borrow
        std::vector<uint8_t, SecureAlloc<uint8_t> > digestCopy(hLen);
        {
            java_buffer digestBuf = java_buffer::from_array(env, digestArr, offset, length);
            jni_borrow digest(env, digestBuf, "digest");
            memcpy(digestCopy.data(), digest.data(), hLen);
        }

        // Allocate output buffer for signature
        size_t maxOut = RSA_size(rsa);
        std::vector<uint8_t, SecureAlloc<uint8_t> > signature(maxOut);
        size_t sigLen = 0;

        // Use AWS-LC's RSA_sign_pss_mgf1 to perform PSS signature
        if (RSA_sign_pss_mgf1(rsa, &sigLen, signature.data(), maxOut, digestCopy.data(), hLen, md, mgf_md, saltLen)
            != 1) {
            throw_openssl("RSA_sign_pss_mgf1 failed");
        }

        signature.resize(sigLen);
        return vecToArray(env, signature);

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_RsaEmsaPss_verifyEmsaPss(JNIEnv* pEnv,
    jclass,
    jlong pKey,
    jlong hashMd,
    jlong mgfMd,
    jint saltLen,
    jbyteArray digestArr,
    jint offset,
    jint length,
    jbyteArray signatureArr,
    jint sigOffset,
    jint sigLength)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(pKey);
        const EVP_MD* md = reinterpret_cast<const EVP_MD*>(hashMd);
        const EVP_MD* mgf_md = reinterpret_cast<const EVP_MD*>(mgfMd);

        if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Key must be RSA");
        }

        // Get RSA key from EVP_PKEY
        RSA* rsa = EVP_PKEY_get0_RSA(key);
        if (rsa == nullptr) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Failed to get RSA key");
        }

        // Get hash length
        size_t hLen = EVP_MD_size(md);

        // Validate digest length
        if ((size_t)length != hLen) {
            throw_java_ex(EX_SIGNATURE_EXCEPTION, "Digest length mismatch");
        }

        // Get digest bytes and copy them
        std::vector<uint8_t, SecureAlloc<uint8_t> > digestCopy(hLen);
        {
            java_buffer digestBuf = java_buffer::from_array(env, digestArr, offset, length);
            jni_borrow digest(env, digestBuf, "digest");
            memcpy(digestCopy.data(), digest.data(), hLen);
        }

        // Get signature bytes and copy them
        std::vector<uint8_t, SecureAlloc<uint8_t> > signatureCopy(sigLength);
        {
            java_buffer signatureBuf = java_buffer::from_array(env, signatureArr, sigOffset, sigLength);
            jni_borrow signature(env, signatureBuf, "signature");
            memcpy(signatureCopy.data(), signature.data(), sigLength);
        }

        // Use AWS-LC's RSA_verify_pss_mgf1 to verify PSS signature
        int result = RSA_verify_pss_mgf1(
            rsa, digestCopy.data(), hLen, md, mgf_md, saltLen, signatureCopy.data(), signatureCopy.size());

        if (result != 1) {
            // Verification failure leaves errors on the OpenSSL error queue.
            // Drain them to prevent abort in extra-checks test builds.
            drainOpensslErrors();
            return JNI_FALSE;
        }

        return JNI_TRUE;

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return JNI_FALSE;
    }
}
