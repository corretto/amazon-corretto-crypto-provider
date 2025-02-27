// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "generated-headers.h"

#include "env.h"
#include "keyutils.h"
#include "util.h"
// JNI methods needed by the Java Utils class rather than generic utilities needed by our code.

using namespace AmazonCorrettoCryptoProvider;

extern "C" {

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getNativeBufferOffset
 * Signature: (Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)J
 */

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getNativeBufferOffset(
    JNIEnv* env, jclass, jobject bufA, jobject bufB)
{
    const jlong JINT_MAX = (1L << 31) - 1L;
    const jlong JINT_MIN = -(1L << 31);
    const jlong no_overlap = JINT_MAX + 1L;

    void* pA = env->GetDirectBufferAddress(bufA);
    void* pB = env->GetDirectBufferAddress(bufB);

    if (!pA || !pB) {
        return no_overlap;
    }

    jlong lenA = env->GetDirectBufferCapacity(bufA);
    jlong lenB = env->GetDirectBufferCapacity(bufB);

    uintptr_t vA = (uintptr_t)pA;
    uintptr_t vB = (uintptr_t)pB;

    ptrdiff_t diff = vB - vA;
    if (diff > 0 && diff >= lenA) {
        // B is located after A's end, so there's no real overlap
        return no_overlap;
    }

    if (diff < 0 && -diff >= lenB) {
        // A is located after B's end, so no real overlap
        return no_overlap;
    }

    // diff should be within jint's bounds now, as direct buffers can't be larger
    // than can be represented by an int
    if (diff < JINT_MIN || diff > JINT_MAX) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Overlap outside range of jint");
    }

    return diff;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getEvpMdFromName
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getEvpMdFromName(
    JNIEnv* pEnv, jclass, jstring mdName)
{
    try {
        raii_env env(pEnv);
        return reinterpret_cast<jlong>(digestFromJstring(env, mdName));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getDigestLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getDigestLength(JNIEnv*, jclass, jlong evpMd)
{
    return EVP_MD_size(reinterpret_cast<const EVP_MD*>(evpMd));
}

/*
 * Class:     com_amazon_corretto_crypto_utils_MlDsaUtils
 * Method:    expandPrivateKeyInternal
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_utils_MlDsaUtils_expandPrivateKeyInternal(
    JNIEnv* pEnv, jclass, jbyteArray keyBytes)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);
        jsize key_der_len = env->GetArrayLength(keyBytes);

        if (key_der_len > 52) { // If they key is already expanded, return it
            return keyBytes;
        }
        CHECK_OPENSSL(key_der_len == 52); // PKCS8-encoded seed keys are always 52 bytes
        uint8_t* key_der = (uint8_t*)env->GetByteArrayElements(keyBytes, nullptr);
        CHECK_OPENSSL(key_der);

        // Parse the seed key
        BIO* key_bio = BIO_new_mem_buf(key_der, key_der_len);
        CHECK_OPENSSL(key_bio);
        PKCS8_PRIV_KEY_INFO_auto pkcs8 = PKCS8_PRIV_KEY_INFO_auto::from(d2i_PKCS8_PRIV_KEY_INFO_bio(key_bio, nullptr));
        CHECK_OPENSSL(pkcs8.isInitialized());
        EVP_PKEY_auto key = EVP_PKEY_auto::from(EVP_PKCS82PKEY(pkcs8));

        // Expand the seed key and encode it before returning
        OPENSSL_buffer_auto new_der;
        int new_der_len = encodeExpandedMLDSAPrivateKey(key, &new_der);
        CHECK_OPENSSL(new_der_len > 0);
        if (!(result = env->NewByteArray(new_der_len))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        env->SetByteArrayRegion(result, 0, new_der_len, (const jbyte*)new_der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_utils_MlDsaUtils
 * Method:    computeMuInternal
 * Signature: ([B[B)[B
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_utils_MlDsaUtils_computeMuInternal(
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
}