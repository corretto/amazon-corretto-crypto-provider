// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef HPKE_SUITES_H
#define HPKE_SUITES_H 1

#include <openssl/hpke.h>
#include <cstdint>

namespace AmazonCorrettoCryptoProvider {
namespace {

    struct HpkeSuiteRow {
        uint16_t kem_id;
        uint16_t kdf_id;
        uint16_t aead_id;
        const EVP_HPKE_KEM* (*kem)(void);
        const EVP_HPKE_KDF* (*kdf)(void);
        const EVP_HPKE_AEAD* (*aead)(void);
    };

    // The base-mode ML-KEM suites this AWS-LC's hpke.h provides; possibly none.
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

} // namespace
} // namespace AmazonCorrettoCryptoProvider

#endif // HPKE_SUITES_H
