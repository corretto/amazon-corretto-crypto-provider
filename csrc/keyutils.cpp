// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "keyutils.h"
#include "auto_free.h"
#include "bn.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace AmazonCorrettoCryptoProvider {

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der,
    const int derLen,
    const int evpType,
    bool shouldCheckPrivate,
    const char* javaExceptionClass)
{
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer

    EVP_PKEY* result = d2i_PrivateKey(evpType, NULL, &der_mutable_ptr, derLen);

    if (der + derLen != der_mutable_ptr) {
        if (result) {
            EVP_PKEY_free(result);
        }
        throw_openssl(javaExceptionClass, "Extra key information");
    }

    if (!result) {
        throw_openssl(javaExceptionClass, "Unable to convert PKCS8_PRIV_KEY_INFO to EVP_PKEY");
    }

    if (EVP_PKEY_base_id(result) == EVP_PKEY_RSA) {
        const RSA* rsa = EVP_PKEY_get0_RSA(result);

        if (rsa) {
            // We need strip zero CRT values which can confuse OpenSSL
            const BIGNUM* n;
            const BIGNUM* e;
            const BIGNUM* d;
            const BIGNUM* p;
            const BIGNUM* q;
            const BIGNUM* dmp1;
            const BIGNUM* dmq1;
            const BIGNUM* iqmp;
            bool need_rebuild = false;

            RSA_get0_key(rsa, &n, &e, &d);
            RSA_get0_factors(rsa, &p, &q);
            RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
            // If blinding is set and any of the parameters required for blinding
            // are NULL, rebuild to turn blinding off. Otherwise, rebuild if any
            // of the params are 0-valued to NULL them out.
            if ((RSA_test_flags(rsa, RSA_FLAG_NO_BLINDING) == 0) && (!e || !p || !q)) {
                need_rebuild = true;
            } else if (e && BN_is_zero(e)) {
                need_rebuild = true;
            } else if (p && BN_is_zero(p)) {
                need_rebuild = true;
            } else if (q && BN_is_zero(q)) {
                need_rebuild = true;
            } else if (dmp1 && BN_is_zero(dmp1)) {
                need_rebuild = true;
            } else if (dmq1 && BN_is_zero(dmq1)) {
                need_rebuild = true;
            } else if (iqmp && BN_is_zero(iqmp)) {
                need_rebuild = true;
            }

            if (need_rebuild) {
                // This key likely only has (n, d) set. Very weird, but it happens in java sometimes.
                RSA_auto nulled_rsa;
                // No need to copy n or d since new_private_RSA_key_with_no_e does not take ownership.
                nulled_rsa.set(new_private_RSA_key_with_no_e(n, d));
                if (e != nullptr && !BN_is_zero(e)) {
                    // Need to copy e since RSA_set0_key takes ownership.
                    BigNumObj e_copy = BigNumObj::fromBIGNUM(e);
                    if (!RSA_set0_key(nulled_rsa, nullptr, e_copy, nullptr)) {
                        throw_openssl("Unable to set e for RSA");
                    }
                    e_copy.releaseOwnership();
                }
                EVP_PKEY_set1_RSA(result, nulled_rsa);
                shouldCheckPrivate = false; // We cannot check private keys without CRT parameters
            }
        }
    }

    if (shouldCheckPrivate && !checkKey(result)) {
        EVP_PKEY_free(result);
        throw_openssl(javaExceptionClass, "Key fails check");
    }

    return result;
}

EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass)
{
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer

    EVP_PKEY* result = d2i_PUBKEY(NULL, &der_mutable_ptr, derLen);
    if (der + derLen != der_mutable_ptr) {
        if (result) {
            EVP_PKEY_free(result);
        }
        throw_openssl(javaExceptionClass, "Extra key information");
    }
    if (!result) {
        throw_openssl(javaExceptionClass, "Unable to parse key");
    }

    if (!checkKey(result)) {
        EVP_PKEY_free(result);
        throw_openssl(javaExceptionClass, "Key fails check");
    }
    return result;
}

bool checkKey(const EVP_PKEY* key)
{
    int keyType = EVP_PKEY_base_id(key);
    bool result = false;

    const RSA* rsaKey;
    const BIGNUM* p;
    const BIGNUM* q;
    const EC_KEY* ecKey;

    switch (keyType) {
    case EVP_PKEY_RSA:
        rsaKey = EVP_PKEY_get0_RSA(key);
        RSA_get0_factors(rsaKey, &p, &q);
        // RSA_check_key only works when sufficient private values are set
        if (p && !BN_is_zero(p) && q && !BN_is_zero(q)) {
            result = RSA_check_key(rsaKey) == 1;
        } else {
            // We don't have enough information to actually check the key
            result = true;
        }

        break;
    case EVP_PKEY_EC:
        ecKey = EVP_PKEY_get0_EC_KEY(key);
        result = EC_KEY_check_key(ecKey) == 1;

        break;
    default:
        // Keys we can't check, we just claim are fine, because there is nothing else we can do.
        result = true;
    }
    return result;
}

const EVP_MD* digestFromJstring(raii_env& env, jstring digestName)
{
    if (!digestName) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Null Digest name");
        return NULL;
    }
    jni_string name(env, digestName);
    const EVP_MD* result = EVP_get_digestbyname(name.native_str);

    if (!result) {
        throw_openssl("Unable to get digest");
    }

    return result;
}

RSA* new_private_RSA_key_with_no_e(BIGNUM const* n, BIGNUM const* d)
{
    RSA* result = ::RSA_new_private_key_no_e(n, d);

    if (result == nullptr) {
        throw_openssl("RSA_new_private_key_no_e failed.");
    }

    return result;
}

#if !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)
size_t encodeExpandedMLDSAPrivateKey(const EVP_PKEY* key, uint8_t** out)
{
    CHECK_OPENSSL(key);
    CHECK_OPENSSL(EVP_PKEY_id(key) == EVP_PKEY_PQDSA);
    CHECK_OPENSSL(out);
    size_t raw_len;
    int nid = NID_undef;
    // See Section 4, Table 2 of https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
    switch (EVP_PKEY_size(key)) { // switch on signature size for |key|'s algorithm
    case 2420:
        nid = NID_MLDSA44;
        raw_len = 2560;
        break;
    case 3309:
        nid = NID_MLDSA65;
        raw_len = 4032;
        break;
    case 4627:
        nid = NID_MLDSA87;
        raw_len = 4896;
        break;
    default:
        throw_java_ex(EX_ILLEGAL_ARGUMENT, "Invalid ML-DSA signature size");
    }
    OPENSSL_buffer_auto raw_expanded(raw_len);
    CHECK_OPENSSL(EVP_PKEY_get_raw_private_key(key, raw_expanded, &raw_len));
    CBB cbb, pkcs8, algorithm, priv, expanded;
    CBB_init(&cbb, 0);
    // Encoding below is based on expandedKey CHOICE member of PrivateKey ASN.1 structures in:
    // https://github.com/lamps-wg/dilithium-certificates/blob/main/X509-ML-DSA-2025.asn
    // spotless:off
    if (!CBB_add_asn1(&cbb, &pkcs8, CBS_ASN1_SEQUENCE) ||
        !CBB_add_asn1_uint64(&pkcs8, 0) ||
        !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
        !OBJ_nid2cbb(&algorithm, nid) ||
        !CBB_add_asn1(&pkcs8, &priv, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_asn1(&priv, &expanded, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&expanded, raw_expanded, raw_len)) {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error serializing expanded ML-DSA key");
    }
    // spotless:on
    size_t out_len;
    if (!CBB_finish(&cbb, out, &out_len)) {
        OPENSSL_free(*out);
        throw_java_ex(EX_RUNTIME_CRYPTO, "Error finalizing expanded ML-DSA key");
    }
    return out_len;
}
#endif // !defined(FIPS_BUILD) || defined(EXPERIMENTAL_FIPS_BUILD)

}
