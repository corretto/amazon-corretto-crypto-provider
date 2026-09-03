// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Public utility methods */
public final class MlDsaUtils {
  private MlDsaUtils() {} // private constructor to prevent instantiation

  private static native byte[] computeMuInternal(byte[] pubKeyEncoded, byte[] message);

  private static native byte[] expandPrivateKeyInternal(byte[] key);

  /**
   * Returns {@code key}'s encoding, rejecting a key this class cannot hand to JNI. Both null checks
   * have to happen in Java: {@code getAlgorithm()} is not specified to be non-null, and {@code
   * getEncoded()} is null for a key that does not support encoding, which in JNI would reach {@code
   * GetArrayLength(nullptr)}.
   */
  private static byte[] requireEncodableMlDsaKey(final Key key) {
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }
    final String algorithm = key.getAlgorithm();
    if (algorithm == null || !algorithm.startsWith("ML-DSA")) {
      throw new IllegalArgumentException("Not an ML-DSA key: " + algorithm);
    }
    final byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new IllegalArgumentException("Key does not support encoding");
    }
    return encoded;
  }

  /**
   * Computes mu as defined on line 6 of Algorithm 7 and line 7 of Algorithm 8 in NIST FIPS 204.
   *
   * <p>See <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>
   *
   * @param publicKey ML-DSA public key
   * @param message byte array of the message over which to compute mu
   * @return a byte[] of length 64 containing mu
   * @throws IllegalArgumentException if {@code publicKey} is null, is not an ML-DSA key (including
   *     one whose {@code getEncoded()} is not an ML-DSA public key), or returns null from {@code
   *     getAlgorithm()} or {@code getEncoded()}, or if {@code message} is null
   * @throws com.amazon.corretto.crypto.provider.RuntimeCryptoException if {@code
   *     publicKey.getEncoded()} is not a X.509 SubjectPublicKeyInfo ACCP can parse
   */
  public static byte[] computeMu(PublicKey publicKey, byte[] message) {
    final byte[] encoded = requireEncodableMlDsaKey(publicKey);
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    return computeMuInternal(encoded, message);
  }

  /**
   * Returns an expanded ML-DSA private key, whether the key passed in is based on a seed or
   * expanded. It returns the PKCS8-encoded expanded key.
   *
   * <p>The returned encoding is always the canonical minimal form: a version 0 {@code
   * PrivateKeyInfo} with no {@code attributes} and no {@code publicKey}. Those optional fields are
   * accepted on input but not carried over, so this is idempotent on its own output rather than
   * byte-preserving on arbitrary input.
   *
   * @param key an ML-DSA private key
   * @return a byte[] containing the PKCS8-encoded expanded private key
   * @throws IllegalArgumentException if {@code key} is null, is not an ML-DSA key, or returns null
   *     from {@code getAlgorithm()} or {@code getEncoded()}
   * @throws com.amazon.corretto.crypto.provider.RuntimeCryptoException if {@code key.getEncoded()}
   *     is not a PKCS8 ML-DSA private key ACCP can parse
   */
  public static byte[] expandPrivateKey(PrivateKey key) {
    return expandPrivateKeyInternal(requireEncodableMlDsaKey(key));
  }
}
