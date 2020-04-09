// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "keyutils.h"

namespace AmazonCorrettoCryptoProvider {

#define BN_null_if_zero(x) do { \
  if ((x) && BN_is_zero(x)) { \
    BN_clear_free(x); \
    x = nullptr; \
  } \
} while(0)

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der, const int derLen, const bool checkPrivateKey, const char* javaExceptionClass) {
  const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer

  PKCS8_PRIV_KEY_INFO* pkcs8Key = d2i_PKCS8_PRIV_KEY_INFO(NULL, &der_mutable_ptr, derLen);
  if (der + derLen != der_mutable_ptr) {
    if (pkcs8Key) {
      PKCS8_PRIV_KEY_INFO_free(pkcs8Key);
    }
      throw_openssl(javaExceptionClass, "Extra key information");
  }
  if (!pkcs8Key) {
      throw_openssl(javaExceptionClass, "Unable to parse DER key into PKCS8_PRIV_KEY_INFO");
  }
  EVP_PKEY* result = EVP_PKCS82PKEY(pkcs8Key);
  PKCS8_PRIV_KEY_INFO_free(pkcs8Key);
  if (!result) {
      throw_openssl(javaExceptionClass, "Unable to convert PKCS8_PRIV_KEY_INFO to EVP_PKEY");
  }

  if (checkPrivateKey && !checkKey(result)) {
      EVP_PKEY_free(result);
      throw_openssl(javaExceptionClass, "Key fails check");
  }

  if (EVP_PKEY_base_id(result) == EVP_PKEY_RSA) {
      const RSA *rsa = EVP_PKEY_get0_RSA(result);

      if (rsa) {
          // We need strip zero CRT values which can confuse OpenSSL
          const BIGNUM *n;
          const BIGNUM *e;
          const BIGNUM *d;
          const BIGNUM *p;
          const BIGNUM *q;
          const BIGNUM *dmp1;
          const BIGNUM *dmq1;
          const BIGNUM *iqmp;
          bool need_rebuild = false;

          RSA_get0_key(rsa, &n, &e, &d);
          RSA_get0_factors(rsa, &p, &q);
          RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
          if (e && BN_is_zero(e)) {
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
            RSA *nulled_rsa = RSA_new();

            if (!RSA_set0_key(nulled_rsa, BN_dup(n), BN_dup(e), BN_dup(d))) {
              throw_openssl(javaExceptionClass, "Unable to set RSA key parameters");
            }
            EVP_PKEY_set1_RSA(result, nulled_rsa);
            RSA_free(nulled_rsa); // Decrement reference counter
            RSA_blinding_off(nulled_rsa);
          }
      }
  }

  return result;
}

EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass) {
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

bool checkKey(EVP_PKEY* key) {
    int keyType = EVP_PKEY_base_id(key);
    bool result = false;

    const RSA* rsaKey;
    const BIGNUM *p;
    const BIGNUM *q;
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
        // DH keys appear to be properly checked upon use (and unit test confirm this behavior).
        result = true;
    }
    return result;
}
}
