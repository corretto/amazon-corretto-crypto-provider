// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import java.security.PrivateKey;

/** Public utility methods for ML-KEM operations. */
public final class MlKemUtils {
  private MlKemUtils() {} // private constructor to prevent instantiation

  private static native byte[] expandPrivateKeyInternal(byte[] key);

  /**
   * Returns an expanded ML-KEM private key, whether the key passed in is based on a seed or
   * expanded. It returns the PKCS8-encoded expanded key.
   *
   * <p>The seed format is a 64-byte value (d || z) as defined in FIPS 203. The expanded
   * decapsulation key is derived using ML-KEM.KeyGen_internal(d, z) (Algorithm 16).
   *
   * <p>See <a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a>
   *
   * <p>See <a href="https://datatracker.ietf.org/doc/rfc9935/">RFC 9935</a>
   *
   * <p>The returned encoding is always the canonical minimal form: a version 0 {@code
   * PrivateKeyInfo} wrapping the {@code expandedKey} CHOICE, with no {@code attributes} and no
   * {@code publicKey}. Those optional {@code OneAsymmetricKey} fields are accepted on input but are
   * not carried over, so this method is idempotent on its own output rather than byte-preserving on
   * arbitrary input. Only the {@code seed} and {@code expandedKey} CHOICEs of RFC 9935 Section 6
   * are accepted; the {@code both} CHOICE is rejected.
   *
   * @param key an ML-KEM private key
   * @return a byte[] containing the PKCS8-encoded expanded private key
   * @throws IllegalArgumentException if {@code key} is null, is not an ML-KEM key, or returns null
   *     from {@code getAlgorithm()} or {@code getEncoded()}
   * @throws com.amazon.corretto.crypto.provider.RuntimeCryptoException if {@code key.getEncoded()}
   *     is not a PKCS8 ML-KEM private key ACCP can parse
   */
  public static byte[] expandPrivateKey(PrivateKey key) {
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }
    // Key.getAlgorithm() is not specified to be non-null, so it cannot be dereferenced directly.
    final String algorithm = key.getAlgorithm();
    if (algorithm == null || !algorithm.startsWith("ML-KEM")) {
      throw new IllegalArgumentException("Not an ML-KEM key: " + algorithm);
    }
    // Key.getEncoded() is specified to return null for a key that does not support encoding, so it
    // has to be checked here rather than in JNI, where it would reach GetArrayLength(nullptr).
    final byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new IllegalArgumentException("Key does not support encoding");
    }
    return expandPrivateKeyInternal(encoded);
  }
}
