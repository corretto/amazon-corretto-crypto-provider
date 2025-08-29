// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public enum MlKemParameter {
  // (parameterSize, publicKeySize, secretKeySize, ciphertextSize, NID Value) -
  // constants defined in AWS-LC
  MLKEM_512(512, 800, 1632, 768, 988),
  MLKEM_768(768, 1184, 2400, 1088, 989),
  MLKEM_1024(1024, 1568, 3168, 1568, 990);

  private final int parameterSize;
  private final int publicKeySize;
  private final int secretKeySize;
  private final int ciphertextSize;
  private final int nid;
  public static final int SHARED_SECRET_SIZE =
      32; // Shared secret size is constant across all parameter sets for

  // ML-KEM

  MlKemParameter(
      int parameterSize, int publicKeySize, int secretKeySize, int ciphertextSize, int nid) {
    this.parameterSize = parameterSize;
    this.publicKeySize = publicKeySize;
    this.secretKeySize = secretKeySize;
    this.ciphertextSize = ciphertextSize;
    this.nid = nid;
  }

  public static MlKemParameter fromParameterSize(int parameterSet) {
    switch (parameterSet) {
      case 512:
        return MLKEM_512;
      case 768:
        return MLKEM_768;
      case 1024:
        return MLKEM_1024;
      default:
        throw new IllegalArgumentException("Invalid ML-KEM parameter set: " + parameterSet);
    }
  }

  public static MlKemParameter fromNid(int nid) {
    switch (nid) {
      case 988:
        return MLKEM_512;
      case 989:
        return MLKEM_768;
      case 990:
        return MLKEM_1024;
      default:
        throw new IllegalArgumentException("Invalid ML-KEM NID: " + nid);
    }
  }

  public int getPublicKeySize() {
    return publicKeySize;
  }

  public int getNid() {
    return nid;
  }

  public int getSecretKeySize() {
    return secretKeySize;
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

  public static MlKemParameter getParameterSet(EvpKeyType type) {
    switch (type) {
      case MLKEM_512:
        return MLKEM_512;
      case MLKEM_768:
        return MLKEM_768;
      case MLKEM_1024:
        return MLKEM_1024;
      default:
        throw new IllegalArgumentException("Unsupported EvpKeyType: " + type);
    }
  }
}
