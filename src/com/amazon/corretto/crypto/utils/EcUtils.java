// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import java.security.PrivateKey;

/** Public utility methods for ECC operations */
public final class EcUtils {
  private EcUtils() {} // private constructor to prevent instantiation

  private static native byte[] encodeRfc5915EcPrivateKeyInternal(byte[] privKeyEncoded);

  /**
   * Returns an EC private key encoded with redundant curve identifier confromant to RFC 5915,
   * similar to BouncyCastle's encoding format.
   *
   * <p>"Though the ASN.1 indicates that the parameters field is OPTIONAL, implementations that
   * conform to this document MUST always include the parameters field."
   *
   * <p>https://datatracker.ietf.org/doc/html/rfc5915#section-3
   *
   * @param privateKey an EC private key
   * @return a byte[] containing the expanded private key encoding
   */
  public static byte[] encodeRfc5915EcPrivateKey(PrivateKey privateKey) {
    if (privateKey == null || !privateKey.getAlgorithm().equals("EC")) {
      throw new IllegalArgumentException("Key must be EC");
    }
    return encodeRfc5915EcPrivateKeyInternal(privateKey.getEncoded());
  }
}
