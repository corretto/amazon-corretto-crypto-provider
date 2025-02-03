// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.KeySpec;
import java.util.Objects;

/**
 * Represents the inputs to CounterKdfSpec algorithms.
 *
 * <p>If info is not provided, an empty byte array is used.
 *
 * <p>The algorithmName is the name of algorithm used to create SecretKeySpec.
 */
public class CounterKdfSpec implements KeySpec {
  private final byte[] secret;
  private final byte[] info;
  private final int outputLen;
  private final String algorithName;

  public CounterKdfSpec(
      final byte[] secret, final byte[] info, final int outputLen, final String algorithName) {
    this.secret = Objects.requireNonNull(secret);
    if (this.secret.length == 0) {
      throw new IllegalArgumentException("Secret must be byte array with non-zero length.");
    }
    this.info = Objects.requireNonNull(info);
    if (outputLen <= 0) {
      throw new IllegalArgumentException("Output size must be greater than zero.");
    }
    this.outputLen = outputLen;
    this.algorithName = Objects.requireNonNull(algorithName);
  }

  public CounterKdfSpec(final byte[] secret, final int outputLen, final String algorithName) {
    this(secret, Utils.EMPTY_ARRAY, outputLen, algorithName);
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

  public String getAlgorithName() {
    return algorithName;
  }
}
