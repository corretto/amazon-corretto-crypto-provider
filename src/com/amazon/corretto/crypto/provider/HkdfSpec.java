// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.KeySpec;

public class HkdfSpec implements KeySpec {
  final int mode;
  final byte[] secretOrPrk;
  final byte[] salt;
  final byte[] info;
  final int desiredLength;
  final String algorithmName;
  public static final String DEFAULT_ALGORITHM_NAME = "Hkdf";
  public static final int HKDF_MODE = 1;
  public static final int HKDF_EXTRACT_MODE = 2;
  public static final int HKDF_EXPAND_MODE = 3;

  public HkdfSpec(
      final int mode,
      final byte[] secret,
      final byte[] salt,
      final byte[] info,
      final byte[] prk,
      final int desiredLength,
      final String algorithmName) {

    switch (mode) {
      case HKDF_MODE:
        this.secretOrPrk = Utils.requireNonNull(secret, "secret cannot be null for HKDF");
        this.salt = Utils.requireNonNull(salt, "salt cannot be null for HKDF");
        this.info = Utils.requireNonNull(info, "info cannot be null for HKDF");
        this.desiredLength = validateDesiredLength(desiredLength);
        break;
      case HKDF_EXTRACT_MODE:
        this.secretOrPrk = Utils.requireNonNull(secret, "secret cannot be null for HKDF_EXTRACT");
        this.salt = Utils.requireNonNull(salt, "salt cannot be null for HKDF_EXTRACT");
        this.info = null;
        this.desiredLength = 0;
        break;
      case HKDF_EXPAND_MODE:
        this.secretOrPrk = Utils.requireNonNull(prk, "prk cannot be null for HKDF_EXPAND");
        this.salt = null;
        this.info = Utils.requireNonNull(info, "info cannot be null for HKDF_EXPAND");
        this.desiredLength = validateDesiredLength(desiredLength);
        break;
      default:
        throw new IllegalArgumentException("mode is not a valid value");
    }
    this.mode = mode;
    this.algorithmName = algorithmName != null ? algorithmName : DEFAULT_ALGORITHM_NAME;
  }

  private static int validateDesiredLength(final int desiredLength) {
    if (desiredLength < 0) {
      throw new IllegalArgumentException("Desired length must be positive");
    }
    return desiredLength;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private int mode;
    private byte[] secret;
    private byte[] salt;
    private byte[] info;
    private byte[] prk;
    private int desiredLength;
    private String algorithmName;

    Builder() {}

    public HkdfSpec build() {
      return new HkdfSpec(mode, secret, salt, info, prk, desiredLength, algorithmName);
    }

    public Builder withMode(final int mode) {
      this.mode = mode;
      return this;
    }

    public Builder withSecret(final byte[] secret) {
      this.secret = secret;
      return this;
    }

    public Builder withSalt(final byte[] salt) {
      this.salt = salt;
      return this;
    }

    public Builder withInfo(final byte[] info) {
      this.info = info;
      return this;
    }

    public Builder withPrk(final byte[] prk) {
      this.prk = prk;
      return this;
    }

    public Builder withDesiredLength(final int desiredLength) {
      this.desiredLength = desiredLength;
      return this;
    }

    public Builder withAlgorithmName(final String algorithmName) {
      this.algorithmName = algorithmName;
      return this;
    }
  }

  public static HkdfSpec hkdfSpec(
      final byte[] secret,
      final byte[] salt,
      final byte[] info,
      final int desiredLength,
      final String algorithmName) {
    return HkdfSpec.builder()
        .withMode(HkdfSpec.HKDF_MODE)
        .withSecret(secret)
        .withSalt(salt)
        .withInfo(info)
        .withDesiredLength(desiredLength)
        .withAlgorithmName(algorithmName)
        .build();
  }

  public static HkdfSpec hkdfExtractSpec(
      final byte[] secret, final byte[] salt, final String algorithmName) {
    return HkdfSpec.builder()
        .withMode(HkdfSpec.HKDF_EXTRACT_MODE)
        .withSecret(secret)
        .withSalt(salt)
        .withAlgorithmName(algorithmName)
        .build();
  }

  public static HkdfSpec hkdfExpandSpec(
      final byte[] prk, final byte[] info, final int desiredLength, final String algorithmName) {
    return HkdfSpec.builder()
        .withMode(HkdfSpec.HKDF_EXPAND_MODE)
        .withPrk(prk)
        .withInfo(info)
        .withDesiredLength(desiredLength)
        .withAlgorithmName(algorithmName)
        .build();
  }
}
