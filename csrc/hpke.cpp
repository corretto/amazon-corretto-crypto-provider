// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/aead.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/mem.h>
#include <memory>
#include <vector>

// Base-mode ML-KEM suites follow hpke.h capabilities, including builds with no available suites.

using namespace AmazonCorrettoCryptoProvider;

#define EX_BADTAG                      "javax/crypto/AEADBadTagException"
#define EX_INVALID_ALGORITHM_PARAMETER "java/security/InvalidAlgorithmParameterException"
#define EX_PROVIDER                    "java/security/ProviderException"

namespace {

struct HpkeSuiteRow {
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
    const EVP_HPKE_KEM* (*kem)(void);
    const EVP_HPKE_KDF* (*kdf)(void);
    const EVP_HPKE_AEAD* (*aead)(void);
};

const HpkeSuiteRow kHpkeSuites[] = {
#if defined(EVP_HPKE_MLKEM768)
    // draft-ietf-hpke-pq ML-KEM-768, HKDF-SHA256, AES-128-GCM.
    { EVP_HPKE_MLKEM768, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM, EVP_hpke_mlkem768, EVP_hpke_hkdf_sha256,
        EVP_hpke_aes_128_gcm },
#endif
#if defined(EVP_HPKE_MLKEM1024) && defined(EVP_HPKE_HKDF_SHA384)
    // draft-ietf-hpke-pq ML-KEM-1024, HKDF-SHA384, AES-256-GCM.
    { EVP_HPKE_MLKEM1024, EVP_HPKE_HKDF_SHA384, EVP_HPKE_AES_256_GCM, EVP_hpke_mlkem1024, EVP_hpke_hkdf_sha384,
        EVP_hpke_aes_256_gcm },
#endif
    // Sentinel: a zero-length array is ill-formed under -pedantic. Every loop stops at it.
    { 0, 0, 0, nullptr, nullptr, nullptr },
};

const HpkeSuiteRow* lookup_suite(jint kem_id, jint kdf_id, jint aead_id)
{
    for (const HpkeSuiteRow* row = kHpkeSuites; row->kem != nullptr; ++row) {
        if (row->kem_id == kem_id && row->kdf_id == kdf_id && row->aead_id == aead_id) {
            return row;
        }
    }
    return nullptr;
}

const HpkeSuiteRow* find_suite(jint kem_id, jint kdf_id, jint aead_id)
{
    const HpkeSuiteRow* row = lookup_suite(kem_id, kdf_id, aead_id);
    if (row != nullptr) {
        return row;
    }
    throw java_ex(EX_ILLEGAL_ARGUMENT, "Unsupported HPKE suite");
}

// Cleanup handles the AEAD; explicitly cleanse the remaining secrets even with custom memory hooks.
void free_hpke_ctx(EVP_HPKE_CTX* ctx)
{
    if (ctx == nullptr) {
        return;
    }
    EVP_HPKE_CTX_cleanup(ctx);
    OPENSSL_cleanse(ctx, sizeof(EVP_HPKE_CTX));
    EVP_HPKE_CTX_free(ctx);
}

typedef std::unique_ptr<EVP_HPKE_CTX, decltype(&free_hpke_ctx)> HpkeCtxPtr;

// True if the oldest error in the queue is an EVP error with one of the two reasons. Does not
// consume the queue.
bool peek_is_evp_reason(int reason1, int reason2)
{
    const uint32_t err = ERR_peek_error();
    return ERR_GET_LIB(err) == ERR_LIB_EVP && (ERR_GET_REASON(err) == reason1 || ERR_GET_REASON(err) == reason2);
}

HpkeCtxPtr new_hpke_ctx()
{
    HpkeCtxPtr ctx(EVP_HPKE_CTX_new(), free_hpke_ctx);
    if (!ctx) {
        throw_java_ex(EX_OOM, "Unable to allocate HPKE context");
    }
    return ctx;
}

typedef std::vector<uint8_t, SecureAlloc<uint8_t> > SecureBytes;

// Metadata and range validation must be complete before entering this scope.
// The callback must not retain the pointer beyond its invocation.
template <typename Callback>
bool with_hpke_array(JNIEnv* env,
    jbyteArray array,
    jsize array_len,
    size_t offset,
    size_t length,
    WipeMode mode,
    const Callback& callback)
{
    if (length == 0) {
        uint8_t scratch = 0;
        return callback(&scratch);
    }
    JByteArrayCritical borrow(env, array, array_len, mode);
    return callback(borrow.get() + offset);
}

// Java resolves partial overlap; shared arrays have matching starts or disjoint ranges.
bool hpke_crypt(raii_env& env,
    EVP_HPKE_CTX* ctx,
    bool seal,
    jbyteArray aadArray,
    jint aadLen,
    jbyteArray inArray,
    jint inOff,
    jint inLen,
    jbyteArray outArray,
    jint outOff,
    size_t out_len,
    size_t* written)
{
    java_buffer aadBuf = java_buffer::from_array(env, aadArray, 0, aadLen);
    java_buffer inBuf = java_buffer::from_array(env, inArray, inOff, inLen);
    java_buffer::from_array(env, outArray, outOff, static_cast<jint>(out_len));
    const bool same_array = env->IsSameObject(inArray, outArray) == JNI_TRUE;
    // Complete JNI metadata calls before acquiring arrays.
    const jsize aadArrayLen = env->GetArrayLength(aadArray);
    const jsize inArrayLen = env->GetArrayLength(inArray);
    const jsize outArrayLen = env->GetArrayLength(outArray);
    const size_t in_start = static_cast<size_t>(inOff);
    const size_t out_start = static_cast<size_t>(outOff);
    JNIEnv* jenv = env.get_env();
    const auto crypt = [&](uint8_t* out_ptr, const uint8_t* in_ptr, const uint8_t* aad_ptr) {
        if (seal) {
            return EVP_HPKE_CTX_seal(ctx, out_ptr, written, out_len, in_ptr, inBuf.len(), aad_ptr, aadBuf.len()) == 1;
        }
        return EVP_HPKE_CTX_open(ctx, out_ptr, written, out_len, in_ptr, inBuf.len(), aad_ptr, aadBuf.len()) == 1;
    };
    if (same_array) {
        // Shared arrays hold plaintext. Acquire once and commit after AAD is released.
        JByteArrayCritical shared(jenv, outArray, outArrayLen, WipeMode::WIPE_OUTPUT);
        uint8_t scratch = 0;
        uint8_t* out_ptr = out_len == 0 ? &scratch : shared.get() + out_start;
        const uint8_t* in_ptr = inBuf.len() == 0 ? &scratch : shared.get() + in_start;
        return with_hpke_array(jenv, aadArray, aadArrayLen, 0, aadBuf.len(), WipeMode::NO_WIPE,
            [&](uint8_t* aad_ptr) { return crypt(out_ptr, in_ptr, aad_ptr); });
    }
    // Nested scopes release AAD and input before sensitive output commits, even on failure.
    return with_hpke_array(jenv, outArray, outArrayLen, out_start, out_len,
        seal ? WipeMode::NO_WIPE : WipeMode::WIPE_OUTPUT, [&](uint8_t* out_ptr) {
            return with_hpke_array(jenv, inArray, inArrayLen, in_start, inBuf.len(),
                seal ? WipeMode::WIPE_INPUT : WipeMode::NO_WIPE, [&](uint8_t* in_ptr) {
                    return with_hpke_array(jenv, aadArray, aadArrayLen, 0, aadBuf.len(), WipeMode::NO_WIPE,
                        [&](uint8_t* aad_ptr) { return crypt(out_ptr, in_ptr, aad_ptr); });
                });
        });
}

} // namespace

extern "C" JNIEXPORT jintArray JNICALL Java_com_amazon_corretto_crypto_provider_HpkeSuite_nativeSuiteLengths(
    JNIEnv* pEnv, jclass, jint kemId, jint kdfId, jint aeadId)
{
    try {
        raii_env env(pEnv);
        const HpkeSuiteRow* suite = lookup_suite(kemId, kdfId, aeadId);
        if (suite == nullptr) {
            return nullptr;
        }
        const EVP_HPKE_KEM* kem = suite->kem();
        const jint lengths[] = {
            static_cast<jint>(EVP_HPKE_KEM_public_key_len(kem)),
            static_cast<jint>(EVP_HPKE_KEM_private_key_len(kem)),
            static_cast<jint>(EVP_HPKE_KEM_enc_len(kem)),
            static_cast<jint>(EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(suite->aead()))),
        };
        const jsize count = sizeof(lengths) / sizeof(lengths[0]);
        jintArray result = env->NewIntArray(count);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate HPKE length array");
        }
        env->SetIntArrayRegion(result, 0, count, lengths);
        env.rethrow_java_exception();
        return result;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return nullptr;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeGenerate(
    JNIEnv* pEnv, jclass, jint kemId, jint kdfId, jint aeadId)
{
    try {
        raii_env env(pEnv);
        const EVP_HPKE_KEM* kem = find_suite(kemId, kdfId, aeadId)->kem();
        EVP_HPKE_KEY_auto key = EVP_HPKE_KEY_auto::from(EVP_HPKE_KEY_new());
        CHECK_OPENSSL(key.isInitialized());
        CHECK_OPENSSL(EVP_HPKE_KEY_generate(key.get(), kem));
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeImport(
    JNIEnv* pEnv, jclass, jint kemId, jint kdfId, jint aeadId, jbyteArray seedArray)
{
    try {
        raii_env env(pEnv);
        const EVP_HPKE_KEM* kem = find_suite(kemId, kdfId, aeadId)->kem();
        java_buffer seedBuf = java_buffer::from_array(env, seedArray);
        if (seedBuf.len() != EVP_HPKE_KEM_private_key_len(kem)) {
            throw_java_ex(EX_INVALID_KEY, "Invalid HPKE private key");
        }
        SecureBuffer<uint8_t, EVP_HPKE_MAX_PRIVATE_KEY_LENGTH> seed;
        seedBuf.get_bytes(env, seed, 0, seedBuf.len());
        EVP_HPKE_KEY_auto key = EVP_HPKE_KEY_auto::from(EVP_HPKE_KEY_new());
        CHECK_OPENSSL(key.isInitialized());
        if (!EVP_HPKE_KEY_init(key.get(), kem, seed, seedBuf.len())) {
            throw_openssl(EX_INVALID_KEY, "Invalid HPKE private key");
        }
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeGetPublicKey(
    JNIEnv* pEnv, jclass, jlong keyPtr)
{
    try {
        raii_env env(pEnv);
        const EVP_HPKE_KEY* key = reinterpret_cast<const EVP_HPKE_KEY*>(keyPtr);
        uint8_t out[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
        size_t out_len = 0;
        CHECK_OPENSSL(EVP_HPKE_KEY_public_key(key, out, &out_len, sizeof(out)));
        return bytesToArray(env, out, out_len);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return nullptr;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeGetPrivateKey(
    JNIEnv* pEnv, jclass, jlong keyPtr)
{
    try {
        raii_env env(pEnv);
        const EVP_HPKE_KEY* key = reinterpret_cast<const EVP_HPKE_KEY*>(keyPtr);
        SecureBuffer<uint8_t, EVP_HPKE_MAX_PRIVATE_KEY_LENGTH> out;
        size_t out_len = 0;
        CHECK_OPENSSL(EVP_HPKE_KEY_private_key(key, out, &out_len, sizeof(out.buf)));
        return bytesToArray(env, out, out_len);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return nullptr;
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HpkePrivateKey_nativeRelease(
    JNIEnv*, jclass, jlong keyPtr)
{
    EVP_HPKE_KEY_free(reinterpret_cast<EVP_HPKE_KEY*>(keyPtr));
}

extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeSetupSender(JNIEnv* pEnv,
    jclass,
    jint kemId,
    jint kdfId,
    jint aeadId,
    jbyteArray recipientPublicKey,
    jbyteArray infoArray,
    jbyteArray encOut)
{
    try {
        raii_env env(pEnv);
        const HpkeSuiteRow* suite = find_suite(kemId, kdfId, aeadId);
        const EVP_HPKE_KEM* kem = suite->kem();
        java_buffer encBuf = java_buffer::from_array(env, encOut);
        if (encBuf.len() != EVP_HPKE_KEM_enc_len(kem)) {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "HPKE encapsulation buffer has the wrong length");
        }
        SecureBytes pub = java_buffer::from_array(env, recipientPublicKey).to_vector(env);
        SecureBytes info = java_buffer::from_array(env, infoArray).to_vector(env);
        HpkeCtxPtr ctx = new_hpke_ctx();
        uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
        size_t enc_len = 0;
        // Classify only errors from this setup call.
        ERR_clear_error();
        if (!EVP_HPKE_CTX_setup_sender(ctx.get(), enc, &enc_len, sizeof(enc), kem, suite->kdf(), suite->aead(),
                pub.data(), pub.size(), info.data(), info.size())) {
            // Malformed peer keys are InvalidKeyException; other failures remain crypto errors.
            if (peek_is_evp_reason(EVP_R_INVALID_PEER_KEY, EVP_R_DECODE_ERROR)) {
                drainOpensslErrors();
                throw_java_ex(EX_INVALID_KEY, "Invalid HPKE public key");
            }
            throw_openssl("Unable to set up HPKE sender");
        }
        if (enc_len != encBuf.len()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected HPKE encapsulation length");
        }
        encBuf.put_bytes(env, enc, 0, enc_len);
        return reinterpret_cast<jlong>(ctx.release());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeSetupRecipient(
    JNIEnv* pEnv, jclass, jlong keyPtr, jint kemId, jint kdfId, jint aeadId, jbyteArray encArray, jbyteArray infoArray)
{
    try {
        raii_env env(pEnv);
        const HpkeSuiteRow* suite = find_suite(kemId, kdfId, aeadId);
        const EVP_HPKE_KEY* key = reinterpret_cast<const EVP_HPKE_KEY*>(keyPtr);
        if (EVP_HPKE_KEM_id(EVP_HPKE_KEY_kem(key)) != suite->kem_id) {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "HPKE key does not match the suite's KEM");
        }
        SecureBytes enc = java_buffer::from_array(env, encArray).to_vector(env);
        SecureBytes info = java_buffer::from_array(env, infoArray).to_vector(env);
        HpkeCtxPtr ctx = new_hpke_ctx();
        ERR_clear_error();
        if (!EVP_HPKE_CTX_setup_recipient(
                ctx.get(), key, suite->kdf(), suite->aead(), enc.data(), enc.size(), info.data(), info.size())) {
            // Invalid encapsulation fails initialization; implicit rejection fails authentication later.
            if (peek_is_evp_reason(EVP_R_INVALID_PEER_KEY, EVP_R_DECODE_ERROR)) {
                drainOpensslErrors();
                throw_java_ex(EX_INVALID_ALGORITHM_PARAMETER, "Invalid HPKE encapsulation");
            }
            throw_openssl("Unable to set up HPKE recipient");
        }
        return reinterpret_cast<jlong>(ctx.release());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeSeal(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jbyteArray aad,
    jint aadLen,
    jbyteArray input,
    jint inputOffset,
    jint inputLen,
    jbyteArray output,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);
        EVP_HPKE_CTX* ctx = reinterpret_cast<EVP_HPKE_CTX*>(ctxPtr);
        const size_t out_len = static_cast<size_t>(inputLen) + EVP_HPKE_CTX_max_overhead(ctx);
        size_t written = 0;
        if (!hpke_crypt(
                env, ctx, true, aad, aadLen, input, inputOffset, inputLen, output, outputOffset, out_len, &written)) {
            drainOpensslErrors();
            throw_java_ex(EX_PROVIDER, "HPKE seal failed");
        }
        return static_cast<jint>(written);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeOpen(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jbyteArray aad,
    jint aadLen,
    jbyteArray input,
    jint inputOffset,
    jint inputLen,
    jbyteArray output,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);
        EVP_HPKE_CTX* ctx = reinterpret_cast<EVP_HPKE_CTX*>(ctxPtr);
        // EVP_HPKE_CTX_max_overhead requires a sender context.
        const size_t overhead = EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(EVP_HPKE_CTX_aead(ctx)));
        if (static_cast<size_t>(inputLen) < overhead) {
            throw_java_ex(EX_BADTAG, "HPKE decryption failed");
        }
        const size_t out_len = static_cast<size_t>(inputLen) - overhead;
        size_t written = 0;
        if (!hpke_crypt(
                env, ctx, false, aad, aadLen, input, inputOffset, inputLen, output, outputOffset, out_len, &written)) {
            drainOpensslErrors();
            throw_java_ex(EX_BADTAG, "HPKE decryption failed");
        }
        return static_cast<jint>(written);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_nativeFreeContext(
    JNIEnv*, jclass, jlong ctxPtr)
{
    free_hpke_ctx(reinterpret_cast<EVP_HPKE_CTX*>(ctxPtr));
}

// Probe AWS-LC directly; using lookup_suite here would make the availability check circular.
extern "C" JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_hpkeSuiteAvailable(
    JNIEnv*, jclass, jint kemId, jint kdfId, jint aeadId)
{
#if defined(EVP_HPKE_MLKEM768)
    if (kemId == EVP_HPKE_MLKEM768 && kdfId == EVP_HPKE_HKDF_SHA256 && aeadId == EVP_HPKE_AES_128_GCM) {
        return EVP_hpke_mlkem768() != nullptr && EVP_hpke_hkdf_sha256() != nullptr && EVP_hpke_aes_128_gcm() != nullptr
            ? JNI_TRUE
            : JNI_FALSE;
    }
#endif
#if defined(EVP_HPKE_MLKEM1024) && defined(EVP_HPKE_HKDF_SHA384)
    if (kemId == EVP_HPKE_MLKEM1024 && kdfId == EVP_HPKE_HKDF_SHA384 && aeadId == EVP_HPKE_AES_256_GCM) {
        return EVP_hpke_mlkem1024() != nullptr && EVP_hpke_hkdf_sha384() != nullptr && EVP_hpke_aes_256_gcm() != nullptr
            ? JNI_TRUE
            : JNI_FALSE;
    }
#endif
    return JNI_FALSE;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_hpkeSealWithSeedForTesting(JNIEnv* pEnv,
    jclass,
    jint kemId,
    jint kdfId,
    jint aeadId,
    jbyteArray recipientPublicKey,
    jbyteArray infoArray,
    jbyteArray seedArray,
    jobjectArray aads,
    jobjectArray plaintexts,
    jbyteArray encOut)
{
    try {
        raii_env env(pEnv);
        const HpkeSuiteRow* suite = find_suite(kemId, kdfId, aeadId);
        const EVP_HPKE_KEM* kem = suite->kem();
        SecureBytes seed = java_buffer::from_array(env, seedArray).to_vector(env);
        if (seed.empty()) {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "Empty HPKE test seed");
        }
        if (aads == nullptr || plaintexts == nullptr) {
            throw_java_ex(EX_NPE, "Null HPKE test messages");
        }
        const jsize count = env->GetArrayLength(plaintexts);
        if (env->GetArrayLength(aads) != count) {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "aads and plaintexts differ in length");
        }
        java_buffer encBuf = java_buffer::from_array(env, encOut);
        if (encBuf.len() != EVP_HPKE_KEM_enc_len(kem)) {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "HPKE encapsulation buffer has the wrong length");
        }
        SecureBytes pub = java_buffer::from_array(env, recipientPublicKey).to_vector(env);
        SecureBytes info = java_buffer::from_array(env, infoArray).to_vector(env);
        HpkeCtxPtr ctx = new_hpke_ctx();
        uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
        size_t enc_len = 0;
        if (!EVP_HPKE_CTX_setup_sender_with_seed_for_testing(ctx.get(), enc, &enc_len, sizeof(enc), kem, suite->kdf(),
                suite->aead(), pub.data(), pub.size(), info.data(), info.size(), seed.data(), seed.size())) {
            throw_openssl("Unable to set up HPKE sender");
        }
        if (enc_len != encBuf.len()) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected HPKE encapsulation length");
        }
        encBuf.put_bytes(env, enc, 0, enc_len);
        jclass byteArrayClass = env->FindClass("[B");
        if (!byteArrayClass) {
            env.rethrow_java_exception();
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unable to find byte[] class");
        }
        jobjectArray result = env->NewObjectArray(count, byteArrayClass, nullptr);
        env->DeleteLocalRef(byteArrayClass);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate HPKE ciphertext array");
        }
        for (jsize i = 0; i < count; i++) {
            jbyteArray aadArray = static_cast<jbyteArray>(env->GetObjectArrayElement(aads, i));
            jbyteArray ptArray = static_cast<jbyteArray>(env->GetObjectArrayElement(plaintexts, i));
            env.rethrow_java_exception();
            SecureBytes aad = java_buffer::from_array(env, aadArray).to_vector(env);
            SecureBytes pt = java_buffer::from_array(env, ptArray).to_vector(env);
            env->DeleteLocalRef(aadArray);
            env->DeleteLocalRef(ptArray);
            SecureBytes ct(pt.size() + EVP_HPKE_CTX_max_overhead(ctx.get()));
            size_t ct_len = 0;
            if (!EVP_HPKE_CTX_seal(
                    ctx.get(), ct.data(), &ct_len, ct.size(), pt.data(), pt.size(), aad.data(), aad.size())) {
                throw_openssl("Unable to seal HPKE message");
            }
            jbyteArray ctArray = bytesToArray(env, ct.data(), ct_len);
            env->SetObjectArrayElement(result, i, ctArray);
            env.rethrow_java_exception();
            env->DeleteLocalRef(ctArray);
        }
        return result;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return nullptr;
}
