// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.KeySpec;
import java.util.Objects;
import java.util.Optional;

/**
 * Represents the inputs to ConcatenationKdf algorithms.
 *
 * <p>When using HMAC variants, salt must be provided. The algorithmName is the name of algorithm
 * used to create SecretKeySpec.
 */
public class ConcatenationKdfSpec implements KeySpec {
  private final byte[] secret;
  private final byte[] info;
  private final Optional<byte[]> salt;
  private final int outputLen;
  private final String algorithmName;

  public ConcatenationKdfSpec(
      final byte[] secret,
      final byte[] info,
      final byte[] salt,
      final int outputLen,
      final String algorithmName) {
    this.secret = Objects.requireNonNull(secret);
    if (this.secret.length == 0) {
      throw new IllegalArgumentException("Secret must be byte array with non-zero length.");
    }
    this.info = Objects.requireNonNull(info);
    this.salt = Optional.ofNullable(salt);
    if (outputLen <= 0) {
      throw new IllegalArgumentException("Output size must be greater than zero.");
    }
    this.outputLen = outputLen;
    this.algorithmName = Objects.requireNonNull(algorithmName);
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

  public Optional<byte[]> getSalt() {
    return salt;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }
}
