// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.lang.reflect.Method;

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
      32; // Shared secret size is constant across all parameter sets for ML-KEM

  MlKemParameter(
      int parameterSize, int publicKeySize, int secretKeySize, int ciphertextSize, int nid) {
    this.parameterSize = parameterSize;
    this.publicKeySize = publicKeySize;
    this.secretKeySize = secretKeySize;
    this.ciphertextSize = ciphertextSize;
    this.nid = nid;
  }

  public static MlKemParameter fromParameterSize(int parameterSet) {
    for (MlKemParameter param : values()) {
      if (param.parameterSize == parameterSet) {
        return param;
      }
    }
    throw new IllegalArgumentException("Invalid ML-KEM parameter set: " + parameterSet);
  }

  public static MlKemParameter fromNid(int nid) {
    for (MlKemParameter param : values()) {
      if (param.nid == nid) {
        return param;
      }
    }
    throw new IllegalArgumentException("Invalid ML-KEM NID: " + nid);
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

  public static MlKemParameter getParamSetFromInternalKey(EvpKey.InternalKey internalKey) {
    try {
      Class<?> kemUtilsClass = Class.forName("com.amazon.corretto.crypto.provider.KemUtils");
      Method method = kemUtilsClass.getDeclaredMethod("nativeGetParameterSet", long.class);
      Integer paramSetInt = internalKey.use(ptr -> (Integer) method.invoke(null, ptr));
      if (paramSetInt == -1) {
        throw new RuntimeCryptoException(
            "Failed to get ML-KEM parameter set. Check for valid input.");
      }

      return MlKemParameter.fromParameterSize(paramSetInt);

    } catch (ClassNotFoundException e) {
      throw new UnsupportedOperationException("ML-KEM not supported on this JDK version", e);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeCryptoException("Failed to initialize ML-KEM key", e);
    }
  }

  public static EvpKeyType getEvpKeyType(EvpKey.InternalKey internalKey) {

    MlKemParameter param = getParamSetFromInternalKey(internalKey);
    switch (param) {
      case MLKEM_512:
        return EvpKeyType.MLKEM_512;
      case MLKEM_768:
        return EvpKeyType.MLKEM_768;
      case MLKEM_1024:
        return EvpKeyType.MLKEM_1024;
      default:
        throw new IllegalArgumentException("Invalid ML-KEM parameter set: " + param);
    }
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
