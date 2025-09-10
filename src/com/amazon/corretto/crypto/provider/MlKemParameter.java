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

  public static MlKemParameter fromKemName(String name) {
    switch (name) {
      case "ML-KEM-512":
        return MLKEM_512;
      case "ML-KEM-768":
        return MLKEM_768;
      case "ML-KEM-1024":
        return MLKEM_1024;
      default:
        throw new IllegalArgumentException("Invalid ML-KEM name: " + name);
    }
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
