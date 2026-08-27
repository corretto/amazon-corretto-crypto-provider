// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

enum MlKemParameter {
  // (parameterSize, publicKeySize, secretKeySize, ciphertextSize) -
  // https://github.com/aws/aws-lc/blob/765955a298614877554522143f12c86200f61551/crypto/fipsmodule/ml_kem/ml_kem.h#L4
  MLKEM_512(512, 800, 1632, 768),
  MLKEM_768(768, 1184, 2400, 1088),
  MLKEM_1024(1024, 1568, 3168, 1568);

  private final int parameterSize;
  private final int publicKeySize;
  private final int secretKeySize;
  private final int ciphertextSize;
  // Shared secret size is constant across all parameter sets for ML-KEM
  public static final int SHARED_SECRET_SIZE = 32;

  MlKemParameter(int parameterSize, int publicKeySize, int secretKeySize, int ciphertextSize) {
    this.parameterSize = parameterSize;
    this.publicKeySize = publicKeySize;
    this.secretKeySize = secretKeySize;
    this.ciphertextSize = ciphertextSize;
  }

  /**
   * As {@link #fromAlgorithmName(String)}, but throws rather than returning null. Delegates so the
   * name-to-parameter-set mapping lives in one place; matching is therefore case-insensitive.
   */
  public static MlKemParameter fromKemName(String name) {
    final MlKemParameter result = fromAlgorithmName(name);
    if (result == null) {
      throw new IllegalArgumentException(
          "Invalid ML-KEM name: " + name + ". Supported names are " + supportedAlgorithmNames());
    }
    return result;
  }

  public int getCiphertextSize() {
    return ciphertextSize;
  }

  public int getParameterSize() {
    return parameterSize;
  }

  public String getAlgorithmName() {
    return "ML-KEM-" + parameterSize;
  }

  /**
   * Case-insensitive match of {@code name} against this parameter set's JCA standard algorithm name
   * (e.g. "ML-KEM-768"). Shared by the KeyPairGenerator ({@code MlKemGen}) and KEM ({@code
   * MlKemSpi}) SPIs so the two code paths agree on which {@code NamedParameterSpec} names they
   * accept. Null-safe: returns false for a null name.
   */
  public boolean matchesAlgorithmName(final String name) {
    return getAlgorithmName().equalsIgnoreCase(name);
  }

  /**
   * Case-insensitive lookup of the parameter set whose JCA standard algorithm name is {@code name},
   * or null if {@code name} does not name a supported parameter set. Unlike {@link
   * #fromKemName(String)} this is case-insensitive and returns null rather than throwing, which
   * suits an SPI deciding whether to accept a caller-supplied {@code NamedParameterSpec} name.
   */
  public static MlKemParameter fromAlgorithmName(final String name) {
    for (final MlKemParameter candidate : values()) {
      if (candidate.matchesAlgorithmName(name)) {
        return candidate;
      }
    }
    return null;
  }

  /**
   * The supported algorithm names, comma-separated, for error messages that would otherwise
   * hardcode (and go stale against) the enum constants.
   */
  public static String supportedAlgorithmNames() {
    final StringBuilder names = new StringBuilder();
    for (final MlKemParameter candidate : values()) {
      if (names.length() > 0) {
        names.append(", ");
      }
      names.append(candidate.getAlgorithmName());
    }
    return names.toString();
  }

  public static MlKemParameter fromKeySize(int keySize) {
    if (keySize == MLKEM_512.publicKeySize || keySize == MLKEM_512.secretKeySize) {
      return MLKEM_512;
    } else if (keySize == MLKEM_768.publicKeySize || keySize == MLKEM_768.secretKeySize) {
      return MLKEM_768;
    } else if (keySize == MLKEM_1024.publicKeySize || keySize == MLKEM_1024.secretKeySize) {
      return MLKEM_1024;
    } else {
      throw new IllegalArgumentException(
          "Cannot determine ML-KEM parameter set from key size: " + keySize);
    }
  }
}
