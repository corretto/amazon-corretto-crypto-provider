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
   * @param key an ML-KEM private key
   * @return a byte[] containing the PKCS8-encoded expanded private key
   */
  public static byte[] expandPrivateKey(PrivateKey key) {
    if (key == null || !key.getAlgorithm().startsWith("ML-KEM")) {
      throw new IllegalArgumentException();
    }
    return expandPrivateKeyInternal(key.getEncoded());
  }
}
