// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.KeySpec;
import java.util.Objects;

/**
 * Represents the inputs to ConcatenationKdf algorithms.
 *
 * <p>If info or salt is not provided, empty byte arrays are used.
 *
 * <p>The algorithmName is the name of algorithm used to create SecretKeySpec.
 */
public class ConcatenationKdfSpec implements KeySpec {
  private final byte[] secret;
  private final int outputLen;
  private final String algorithmName;
  private final byte[] info;
  private final byte[] salt;

  public ConcatenationKdfSpec(
      final byte[] secret,
      final int outputLen,
      final String algorithmName,
      final byte[] info,
      final byte[] salt) {
    this.secret = Objects.requireNonNull(secret);
    if (this.secret.length == 0) {
      throw new IllegalArgumentException("Secret must be byte array with non-zero length.");
    }
    if (outputLen <= 0) {
      throw new IllegalArgumentException("Output size must be greater than zero.");
    }
    this.outputLen = outputLen;
    this.algorithmName = Objects.requireNonNull(algorithmName);
    this.info = Objects.requireNonNull(info);
    this.salt = Objects.requireNonNull(salt);
  }

  public ConcatenationKdfSpec(
      final byte[] secret, final int outputLen, final String algorithmName) {
    this(secret, outputLen, algorithmName, Utils.EMPTY_ARRAY, Utils.EMPTY_ARRAY);
  }

  public ConcatenationKdfSpec(
      final byte[] secret, final int outputLen, final String algorithmName, final byte[] info) {
    this(secret, outputLen, algorithmName, info, Utils.EMPTY_ARRAY);
  }

  public byte[] getSecret() {
    return secret;
  }

  public byte[] getInfo() {
    return info;
  }

  public int getOutputLen() {
    return outputLen;
  }

  public byte[] getSalt() {
    return salt;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }
}
