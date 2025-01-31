// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

/** Public utility methods */
public class PublicUtils {
  private PublicUtils() {} // private constructor to prevent instantiation

  /**
   * Computes µ as defined on line 6 of Algorithm 7 and line 7 of Algorithm 8 in NIST FIPS 204.
   *
   * @param pubKeyEncoded X509-encoded of the ML-DSA public key
   * @param message byte array of the message over which to compute µ
   * @return a byte[] of length 64 containing µ
   * @see https://csrc.nist.gov/pubs/fips/204/final
   */
  public static native byte[] computeMLDSAMu(byte[] pubKeyEncoded, byte[] message);
}
