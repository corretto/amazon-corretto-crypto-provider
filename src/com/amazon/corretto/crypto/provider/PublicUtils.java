// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

/** Public utility methods */
public class PublicUtils {
  private PublicUtils() {} // private constructor to prevent instantiation

  private static native byte[] computeMLDSAMuInternal(byte[] pubKeyEncoded, byte[] message);

  /**
   * Computes mu as defined on line 6 of Algorithm 7 and line 7 of Algorithm 8 in NIST FIPS 204.
   *
   * <p>See <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>
   *
   * @param publicKey ML-DSA public key
   * @param message byte array of the message over which to compute mu
   * @return a byte[] of length 64 containing mu
   */
  public static byte[] computeMLDSAMu(PublicKey publicKey, byte[] message) {
    if (!"ML-DSA".equals(publicKey.getAlgorithm()) || message == null) {
      throw new IllegalArgumentException();
    }
    return computeMLDSAMuInternal(publicKey.getEncoded(), message);
  }
}
