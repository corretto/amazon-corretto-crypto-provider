// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
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

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der, const int derLen, const bool shouldCheckPrivate, const char* javaExceptionClass) {
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

  if (shouldCheckPrivate && !checkPrivateKey(result))
  {
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

  if (!checkPublicKey(result)) {
      EVP_PKEY_free(result);
      throw_openssl(javaExceptionClass, "Key fails check");
  }
  return result;
}

bool checkPublicKey(EVP_PKEY *key)
{
  // We can only check EVP_PKEY_CTX objects
  EvpKeyContext ctx;
  ctx.setKeyCtx(EVP_PKEY_CTX_new(key, NULL));
  if (unlikely(ctx.getKeyCtx() == NULL))
  {
    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to create EVP_PKEY_CTX");
  }
  int opensslResult = EVP_PKEY_public_check(ctx.getKeyCtx());
  //  1: Success
  // -2: Key type cannot be checked (so we'll let it through)
  if (opensslResult == -2) {
    // Clear the error queue since we know why it happened
    ERR_clear_error();
    opensslResult = 1;
  }

  return opensslResult == 1;
}

bool checkPrivateKey(EVP_PKEY* key) {
  // We can only check EVP_PKEY_CTX objects
  EvpKeyContext ctx;
  ctx.setKeyCtx(EVP_PKEY_CTX_new(key, NULL));
  if (unlikely(ctx.getKeyCtx() == NULL)) {
    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to create EVP_PKEY_CTX");
  }
  int opensslResult = EVP_PKEY_check(ctx.getKeyCtx());
  //  1: Success
  // -2: Key type cannot be checked (so we'll let it through)
  // Anything else: Error
  return (opensslResult == 1 || opensslResult == -2);
}
}
