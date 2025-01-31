// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

/** Public utility methods */
public class PublicUtils {
  private PublicUtils() {} // private constructor to prevent instantiation

  /**
   * Computes mu as defined on line 6 of Algorithm 7 and line 7 of Algorithm 8 in NIST FIPS 204.
   *
   * <p>See <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>
   *
   * @param pubKeyEncoded X509-encoded of the ML-DSA public key
   * @param message byte array of the message over which to compute mu
   * @return a byte[] of length 64 containing mu
   */
  public static native byte[] computeMLDSAMu(byte[] pubKeyEncoded, byte[] message);
}
