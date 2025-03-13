// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import java.security.PrivateKey;
import java.security.PublicKey;

/** Public utility methods */
public final class MlDsaUtils {
  private MlDsaUtils() {} // private constructor to prevent instantiation

  private static native byte[] computeMuInternal(byte[] pubKeyEncoded, byte[] message);

  private static native byte[] expandPrivateKeyInternal(byte[] key);

  /**
   * Computes mu as defined on line 6 of Algorithm 7 and line 7 of Algorithm 8 in NIST FIPS 204.
   *
   * <p>See <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>
   *
   * @param publicKey ML-DSA public key
   * @param message byte array of the message over which to compute mu
   * @return a byte[] of length 64 containing mu
   */
  public static byte[] computeMu(PublicKey publicKey, byte[] message) {
    if (publicKey == null || !publicKey.getAlgorithm().startsWith("ML-DSA") || message == null) {
      throw new IllegalArgumentException();
    }
    return computeMuInternal(publicKey.getEncoded(), message);
  }

  /**
   * Returns an expanded ML-DSA private key, whether the key passed in is based on a seed or
   * expanded. It returns the PKCS8-encoded expanded key.
   *
   * @param key an ML-DSA private key
   * @return a byte[] containing the PKCS8-encoded seed private key
   */
  public static byte[] expandPrivateKey(PrivateKey key) {
    if (key == null || !key.getAlgorithm().startsWith("ML-DSA")) {
      throw new IllegalArgumentException();
    }
    return expandPrivateKeyInternal(key.getEncoded());
  }
}
