// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    throw_java_ex(javaExceptionClass, "Extra key information");
  }
  if (!pkcs8Key) {
    throw_openssl(javaExceptionClass, "Unable to parse key");
  }
  EVP_PKEY* result = EVP_PKCS82PKEY(pkcs8Key);
  PKCS8_PRIV_KEY_INFO_free(pkcs8Key);

  if (checkPrivateKey && !checkKey(result)) {
      EVP_PKEY_free(result);
      throw_openssl(javaExceptionClass, "Key fails check");
  }

  if (EVP_PKEY_base_id(result) == EVP_PKEY_RSA) {
      RSA *rsa = EVP_PKEY_get1_RSA(result);

      if (rsa) {
          // We need strip zero CRT values which can confuse OpenSSL
          BN_null_if_zero(rsa->e);
          BN_null_if_zero(rsa->p);
          BN_null_if_zero(rsa->q);
          BN_null_if_zero(rsa->dmp1);
          BN_null_if_zero(rsa->dmq1);
          BN_null_if_zero(rsa->iqmp);

          if (rsa->e) {
              RSA_blinding_on(rsa, NULL);
          } else {
              RSA_blinding_off(rsa);
          }

          // get1_RSA incremented the key's reference count, so we need to free to decrement it again
          RSA_free(rsa);
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
    throw_java_ex(javaExceptionClass, "Extra key information");
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

    RSA* rsaKey;
    EC_KEY* ecKey;

    switch (keyType) {
    case EVP_PKEY_RSA:
        rsaKey = EVP_PKEY_get1_RSA(key);
        // RSA_check_key only works when sufficient private values are set
        if (rsaKey->p && !BN_is_zero(rsaKey->p) && rsaKey->q && !BN_is_zero(rsaKey->q)) {
            result = RSA_check_key(rsaKey) == 1;
        } else {
            // We don't have enough information to actually check the key
            result = true;
        }
        RSA_free(rsaKey);
        break;
    case EVP_PKEY_EC:
        ecKey = EVP_PKEY_get1_EC_KEY(key);
        result = EC_KEY_check_key(ecKey) == 1;

        EC_KEY_free(ecKey);
        break;
    default:
        // Keys we can't check, we just claim are fine, because there is nothing else we can do.
        // DH keys appear to be properly checked upon use (and unit test confirm this behavior).
        result = true;
    }
    return result;
}
}
