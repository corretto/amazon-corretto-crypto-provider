// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

class HmacWithPrecomputedKeyKeyFactorySpi extends SecretKeyFactorySpi {

  private final long evpMd;
  private final int precomputedKeyLength;
  private final String algorithmName;

  /**
   * Compute the HMAC precomputed key for digest {@code evpMd} and HMAC key {@code key} and store it
   * in {@code result}.
   *
   * @param output resulting precomputed key
   * @param outputLen length of output
   * @param key input key
   * @param keyLen length of key
   * @param evpMd digest used
   */
  private static native void getPrecomputedKey(
      byte[] output, int outputLen, byte[] key, int keyLen, long evpMd);

  private HmacWithPrecomputedKeyKeyFactorySpi(final String algorithmName, final String digestName) {
    this.evpMd = Utils.getEvpMdFromName(digestName);
    this.precomputedKeyLength = EvpHmac.getPrecomputedKeyLength(digestName);
    this.algorithmName = algorithmName;
  }

  @Override
  protected SecretKey engineGenerateSecret(final KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof SecretKeySpec)) {
      throw new InvalidKeySpecException("KeySpec must be an instance of SecretKeySpec");
    }
    final SecretKeySpec spec = (SecretKeySpec) keySpec;

    if (!"RAW".equalsIgnoreCase(spec.getFormat())) {
      throw new InvalidKeySpecException("KeySpec must support RAW encoding");
    }

    byte[] precomputedKey = new byte[precomputedKeyLength];

    byte[] key = spec.getEncoded();
    if (key == null) {
      throw new InvalidKeySpecException("Key encoding must not be null");
    }
    getPrecomputedKey(precomputedKey, precomputedKeyLength, key, key.length, evpMd);

    return new SecretKeySpec(precomputedKey, algorithmName);
  }

  @Override
  protected KeySpec engineGetKeySpec(final SecretKey key, final Class<?> keySpec) {
    throw new UnsupportedOperationException();
  }

  @Override
  protected SecretKey engineTranslateKey(final SecretKey key) {
    throw new UnsupportedOperationException();
  }

  static final Map<String, HmacWithPrecomputedKeyKeyFactorySpi> INSTANCES = getInstances();

  private static final String MD5_DIGEST_NAME = "md5";
  private static final String SHA1_DIGEST_NAME = "sha1";
  private static final String SHA256_DIGEST_NAME = "sha256";
  private static final String SHA384_DIGEST_NAME = "sha384";
  private static final String SHA512_DIGEST_NAME = "sha512";

  private static Map<String, HmacWithPrecomputedKeyKeyFactorySpi> getInstances() {
    final Map<String, HmacWithPrecomputedKeyKeyFactorySpi> result = new HashMap<>();
    result.put(
        getSpiFactoryForAlgName(EvpHmac.HMAC_MD5_WITH_PRECOMPUTED_KEY),
        new HmacWithPrecomputedKeyKeyFactorySpi(
            EvpHmac.HMAC_MD5_WITH_PRECOMPUTED_KEY, MD5_DIGEST_NAME));
    result.put(
        getSpiFactoryForAlgName(EvpHmac.HMAC_SHA1_WITH_PRECOMPUTED_KEY),
        new HmacWithPrecomputedKeyKeyFactorySpi(
            EvpHmac.HMAC_SHA1_WITH_PRECOMPUTED_KEY, SHA1_DIGEST_NAME));
    result.put(
        getSpiFactoryForAlgName(EvpHmac.HMAC_SHA256_WITH_PRECOMPUTED_KEY),
        new HmacWithPrecomputedKeyKeyFactorySpi(
            EvpHmac.HMAC_SHA256_WITH_PRECOMPUTED_KEY, SHA256_DIGEST_NAME));
    result.put(
        getSpiFactoryForAlgName(EvpHmac.HMAC_SHA384_WITH_PRECOMPUTED_KEY),
        new HmacWithPrecomputedKeyKeyFactorySpi(
            EvpHmac.HMAC_SHA384_WITH_PRECOMPUTED_KEY, SHA384_DIGEST_NAME));
    result.put(
        getSpiFactoryForAlgName(EvpHmac.HMAC_SHA512_WITH_PRECOMPUTED_KEY),
        new HmacWithPrecomputedKeyKeyFactorySpi(
            EvpHmac.HMAC_SHA512_WITH_PRECOMPUTED_KEY, SHA512_DIGEST_NAME));
    return Collections.unmodifiableMap(result);
  }

  static String getSpiFactoryForAlgName(final String alg) {
    return alg.toUpperCase();
  }
}
