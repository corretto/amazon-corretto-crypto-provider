// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

// EMSA-PSS-ENCODE per RFC 8017 §9.1.1
// Returns the encoded message EM ready for raw RSA signing
std::vector<uint8_t, SecureAlloc<uint8_t> > emsaPssEncode(
    raii_env& env, const uint8_t* mHash, size_t hLen, const EVP_MD* md, const EVP_MD* mgfMd, int saltLen, size_t emBits)
{
    // Step 1: Compute emLen = ceil(emBits / 8)
    size_t emLen = (emBits + 7) / 8;

    if (emLen < hLen + saltLen + 2) {
        throw_java_ex(EX_SIGNATURE_EXCEPTION, "Encoding error: emLen too short");
    }

    // Step 2: Generate random salt
    std::vector<uint8_t, SecureAlloc<uint8_t> > salt(saltLen);
    if (saltLen > 0) {
        if (RAND_bytes(salt.data(), saltLen) != 1) {
            throw_openssl("Failed to generate salt");
        }
    }

    // Step 3: Compute M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    std::vector<uint8_t, SecureAlloc<uint8_t> > mPrime(8 + hLen + saltLen);
    memset(mPrime.data(), 0, 8);
    memcpy(mPrime.data() + 8, mHash, hLen);
    if (saltLen > 0) {
        memcpy(mPrime.data() + 8 + hLen, salt.data(), saltLen);
    }

    // Step 4: Compute H = Hash(M')
    std::vector<uint8_t, SecureAlloc<uint8_t> > H(hLen);
    unsigned int hOutLen = 0;
    if (EVP_Digest(mPrime.data(), mPrime.size(), H.data(), &hOutLen, md, nullptr) != 1) {
        throw_openssl("Failed to hash M'");
    }
    if (hOutLen != hLen) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Hash length mismatch");
    }

    // Step 5: Generate DB = PS || 0x01 || salt
    size_t psLen = emLen - saltLen - hLen - 2;
    std::vector<uint8_t, SecureAlloc<uint8_t> > DB(emLen - hLen - 1);
    memset(DB.data(), 0, psLen);
    DB[psLen] = 0x01;
    if (saltLen > 0) {
        memcpy(DB.data() + psLen + 1, salt.data(), saltLen);
    }

    // Step 6: Compute dbMask = MGF1(H, emLen - hLen - 1)
    std::vector<uint8_t, SecureAlloc<uint8_t> > dbMask(DB.size());
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (PKCS1_MGF1(dbMask.data(), dbMask.size(), H.data(), H.size(), mgfMd) != 1) {
        throw_openssl("MGF1 failed");
    }
#pragma clang diagnostic pop

    // Step 7: Compute maskedDB = DB ⊕ dbMask
    std::vector<uint8_t, SecureAlloc<uint8_t> > maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); i++) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    // Step 8: Set leftmost 8 * emLen - emBits bits of maskedDB to zero
    size_t numZeroBits = 8 * emLen - emBits;
    if (numZeroBits > 0) {
        maskedDB[0] &= (0xFF >> numZeroBits);
    }

    // Step 9: Construct EM = maskedDB || H || 0xbc
    std::vector<uint8_t, SecureAlloc<uint8_t> > EM(emLen);
    memcpy(EM.data(), maskedDB.data(), maskedDB.size());
    memcpy(EM.data() + maskedDB.size(), H.data(), H.size());
    EM[emLen - 1] = 0xbc;

    return EM;
}

// EMSA-PSS-VERIFY per RFC 8017 §9.1.2
// Returns true if the signature is valid, false otherwise
bool emsaPssVerify(raii_env& env,
    const uint8_t* mHash,
    size_t hLen,
    const EVP_MD* md,
    const EVP_MD* mgfMd,
    int saltLen,
    const uint8_t* EM,
    size_t emLen,
    size_t emBits)
{
    // Step 1: Check if emLen >= hLen + saltLen + 2
    if (emLen < hLen + saltLen + 2) {
        return false;
    }

    // Step 2: Check if rightmost octet is 0xbc
    if (EM[emLen - 1] != 0xbc) {
        return false;
    }

    // Step 3: Parse EM = maskedDB || H || 0xbc
    size_t maskedDBLen = emLen - hLen - 1;
    const uint8_t* maskedDB = EM;
    const uint8_t* H = EM + maskedDBLen;

    // Step 4: Check if leftmost 8 * emLen - emBits bits are zero
    size_t numZeroBits = 8 * emLen - emBits;
    if (numZeroBits > 0) {
        uint8_t mask = 0xFF << (8 - numZeroBits);
        if ((maskedDB[0] & mask) != 0) {
            return false;
        }
    }

    // Step 5: Compute dbMask = MGF1(H, emLen - hLen - 1)
    std::vector<uint8_t, SecureAlloc<uint8_t> > dbMask(maskedDBLen);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (PKCS1_MGF1(dbMask.data(), dbMask.size(), H, hLen, mgfMd) != 1) {
        throw_openssl("MGF1 failed");
    }
#pragma clang diagnostic pop

    // Step 6: Compute DB = maskedDB ⊕ dbMask
    std::vector<uint8_t, SecureAlloc<uint8_t> > DB(maskedDBLen);
    for (size_t i = 0; i < maskedDBLen; i++) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    // Step 7: Set leftmost 8 * emLen - emBits bits of DB to zero
    if (numZeroBits > 0) {
        DB[0] &= (0xFF >> numZeroBits);
    }

    // Step 8: Check DB = PS || 0x01 || salt
    size_t psLen = emLen - hLen - saltLen - 2;
    for (size_t i = 0; i < psLen; i++) {
        if (DB[i] != 0) {
            return false;
        }
    }
    if (DB[psLen] != 0x01) {
        return false;
    }

    // Step 9: Extract salt
    const uint8_t* salt = DB.data() + psLen + 1;

    // Step 10: Compute M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    std::vector<uint8_t, SecureAlloc<uint8_t> > mPrime(8 + hLen + saltLen);
    memset(mPrime.data(), 0, 8);
    memcpy(mPrime.data() + 8, mHash, hLen);
    if (saltLen > 0) {
        memcpy(mPrime.data() + 8 + hLen, salt, saltLen);
    }

    // Step 11: Compute H' = Hash(M')
    std::vector<uint8_t, SecureAlloc<uint8_t> > HPrime(hLen);
    unsigned int hOutLen = 0;
    if (EVP_Digest(mPrime.data(), mPrime.size(), HPrime.data(), &hOutLen, md, nullptr) != 1) {
        throw_openssl("Failed to hash M'");
    }
    if (hOutLen != hLen) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Hash length mismatch");
    }

    // Step 12: Compare H' with H using constant-time comparison
    if (CRYPTO_memcmp(H, HPrime.data(), hLen) != 0) {
        return false;
    }

    return true;
}

} // anonymous namespace

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_signEmsaPss(JNIEnv* pEnv,
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

        // Get RSA key size in bits
        int keyBits = EVP_PKEY_bits(key);

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

        // Perform EMSA-PSS encoding
        std::vector<uint8_t, SecureAlloc<uint8_t> > EM
            = emsaPssEncode(env, digestCopy.data(), hLen, md, mgf_md, saltLen, keyBits - 1);

        // Perform raw RSA signature (no padding)
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
        if (pctx == nullptr) {
            throw_openssl("Failed to create PKEY_CTX");
        }

        if (EVP_PKEY_sign_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl("Failed to initialize signing");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl("Failed to set padding");
        }

        size_t sigLen;
        if (EVP_PKEY_sign(pctx, nullptr, &sigLen, EM.data(), EM.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl("Failed to get signature length");
        }

        std::vector<uint8_t, SecureAlloc<uint8_t> > signature(sigLen);
        if (EVP_PKEY_sign(pctx, signature.data(), &sigLen, EM.data(), EM.size()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw_openssl("Failed to sign");
        }

        EVP_PKEY_CTX_free(pctx);

        signature.resize(sigLen);
        return vecToArray(env, signature);

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureRaw_verifyEmsaPss(JNIEnv* pEnv,
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

        // Get RSA key size in bits
        int keyBits = EVP_PKEY_bits(key);

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

        // Recover EM from signature
        std::vector<uint8_t, SecureAlloc<uint8_t> > EM;
        {
            // Get signature bytes
            java_buffer signatureBuf = java_buffer::from_array(env, signatureArr, sigOffset, sigLength);
            jni_borrow signature(env, signatureBuf, "signature");

            // Perform raw RSA verification (no padding) to recover EM
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
            if (pctx == nullptr) {
                throw_openssl("Failed to create PKEY_CTX");
            }

            if (EVP_PKEY_verify_recover_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw_openssl("Failed to initialize verification");
            }

            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw_openssl("Failed to set padding");
            }

            size_t emLen;
            if (EVP_PKEY_verify_recover(pctx, nullptr, &emLen, signature.data(), signature.len()) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                // Signature verification can fail legitimately
                unsigned long errorCode = drainOpensslErrors();
                if (RSA_R_MISMATCHED_SIGNATURE == (errorCode & RSA_R_MISMATCHED_SIGNATURE)
                    || EVP_R_INVALID_SIGNATURE == (errorCode & EVP_R_INVALID_SIGNATURE)) {
                    return false;
                }
                return false;
            }

            EM.resize(emLen);
            if (EVP_PKEY_verify_recover(pctx, EM.data(), &emLen, signature.data(), signature.len()) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                unsigned long errorCode = drainOpensslErrors();
                if (RSA_R_MISMATCHED_SIGNATURE == (errorCode & RSA_R_MISMATCHED_SIGNATURE)
                    || EVP_R_INVALID_SIGNATURE == (errorCode & EVP_R_INVALID_SIGNATURE)) {
                    return false;
                }
                return false;
            }

            EVP_PKEY_CTX_free(pctx);

            EM.resize(emLen);
        }

        // Perform EMSA-PSS verification
        bool result
            = emsaPssVerify(env, digestCopy.data(), hLen, md, mgf_md, saltLen, EM.data(), EM.size(), keyBits - 1);

        return result ? JNI_TRUE : JNI_FALSE;

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return JNI_FALSE;
    }
}
