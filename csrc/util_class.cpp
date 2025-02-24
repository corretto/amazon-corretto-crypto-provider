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

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_PublicUtils_expandMLDSAKeyInternal(
    JNIEnv* pEnv, jclass, jbyteArray keyBytes)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);
        jsize key_der_len = env->GetArrayLength(keyBytes);
        // If they key is already expanded, return it
        if (key_der_len > 52) {
            return keyBytes;
        }
        // PKCS8-encoded seed keys are always 52 bytes
        CHECK_OPENSSL(key_der_len == 52);
        uint8_t* key_der = (uint8_t*)env->GetByteArrayElements(keyBytes, nullptr);
        CHECK_OPENSSL(key_der);
        // Parse the seed key
        BIO* key_bio = BIO_new_mem_buf(key_der, key_der_len);
        CHECK_OPENSSL(key_bio);
        PKCS8_PRIV_KEY_INFO_auto pkcs8 = PKCS8_PRIV_KEY_INFO_auto::from(d2i_PKCS8_PRIV_KEY_INFO_bio(key_bio, nullptr));
        CHECK_OPENSSL(pkcs8.isInitialized());
        // Re-serialize into expanded key with |EVP__marshal_private_key|
        CBB cbb;
        CBB_init(&cbb, 0);
        EVP_PKEY_auto key = EVP_PKEY_auto::from(EVP_PKCS82PKEY(pkcs8));
        CHECK_OPENSSL(EVP_marshal_private_key(&cbb, key));
        // |cbb| has allocated its own memory outside of |env|, so copy its contents  over before
        // freeing |cbb|'s buffer with |CBB_cleanup|.
        int new_der_len = CBB_len(&cbb);
        uint8_t* new_der = (uint8_t*)OPENSSL_malloc(new_der_len);
        memcpy(new_der, CBB_data(&cbb), new_der_len);
        CBB_cleanup(&cbb);

        CHECK_OPENSSL(new_der_len > 0);
        if (!(result = env->NewByteArray(new_der_len))) {
            OPENSSL_free(new_der);
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        env->SetByteArrayRegion(result, 0, new_der_len, (const jbyte*)new_der);
        OPENSSL_free(new_der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
    return result;
}
}