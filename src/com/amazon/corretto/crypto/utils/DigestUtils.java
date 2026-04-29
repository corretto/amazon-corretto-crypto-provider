// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.utils;

import com.amazon.corretto.crypto.provider.Utils;

/** Public utility methods for message digest operations. */
public final class DigestUtils {
  private DigestUtils() {} // private constructor to prevent instantiation

  private static native byte[] digestInfoWrapInternal(String digestName, byte[] digestBytes);

  /**
   * Returns the PKCS#1 v1.5 DigestInfo DER encoding of {@code digestBytes} under the hash algorithm
   * named by {@code digestName}. That is, the output is the DER encoding of
   *
   * <pre>
   *   DigestInfo ::= SEQUENCE {
   *     digestAlgorithm AlgorithmIdentifier,
   *     digest          OCTET STRING
   *   }
   * </pre>
   *
   * as defined in RFC 8017 Sec. 9.2. The DER encoding is produced by AWS-LC's {@code
   * RSA_add_pkcs1_prefix}.
   *
   * @param digestName the JCE name of the hash algorithm (e.g. {@code "SHA-256"}, {@code
   *     "SHA-512/256"}, {@code "SHA3-256"})
   * @param digestBytes the raw digest bytes; length must match the output length of the algorithm
   *     named by {@code digestName}
   * @return the DER-encoded DigestInfo
   * @throws IllegalArgumentException if {@code digestName} or {@code digestBytes} is null, if
   *     {@code digestName} is not a supported hash, or if {@code digestBytes} does not match the
   *     expected digest length
   */
  public static byte[] digestInfoWrap(String digestName, byte[] digestBytes) {
    if (digestName == null) {
      throw new IllegalArgumentException("digestName must not be null");
    }
    if (digestBytes == null) {
      throw new IllegalArgumentException("digestBytes must not be null");
    }
    return digestInfoWrapInternal(Utils.jceDigestNameToAwsLcName(digestName), digestBytes);
  }
}
