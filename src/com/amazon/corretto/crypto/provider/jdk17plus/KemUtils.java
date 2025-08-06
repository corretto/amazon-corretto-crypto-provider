// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/** Utility class containing ML-KEM constants from aws-lc/crypto/fipsmodule/ml_kem/ml_kem.h . */
public final class KemUtils {

  private KemUtils() {}

  public static final int SHARED_SECRET_SIZE = 32;

  public static final int MLKEM_512 = 512;
  public static final int MLKEM_768 = 768;
  public static final int MLKEM_1024 = 1024;

  public static final int MLKEM512_PUBLIC_KEY_BYTES = 800;
  public static final int MLKEM512_SECRET_KEY_BYTES = 1632;
  public static final int MLKEM512_CIPHERTEXT_BYTES = 768;

  public static final int MLKEM768_PUBLIC_KEY_BYTES = 1184;
  public static final int MLKEM768_SECRET_KEY_BYTES = 2400;
  public static final int MLKEM768_CIPHERTEXT_BYTES = 1088;

  public static final int MLKEM1024_PUBLIC_KEY_BYTES = 1568;
  public static final int MLKEM1024_SECRET_KEY_BYTES = 3168;
  public static final int MLKEM1024_CIPHERTEXT_BYTES = 1568;

  static native int nativeGetParameterSet(long keyPtr);

  /**
   * Get public key size for the given parameter set.
   *
   * @param parameterSet ML-KEM parameter set (512, 768, or 1024)
   * @return public key size in bytes
   * @throws IllegalArgumentException if parameter set is invalid
   */
  public static int getPublicKeySize(int parameterSet) {
    switch (parameterSet) {
      case MLKEM_512:
        return MLKEM512_PUBLIC_KEY_BYTES;
      case MLKEM_768:
        return MLKEM768_PUBLIC_KEY_BYTES;
      case MLKEM_1024:
        return MLKEM1024_PUBLIC_KEY_BYTES;
      default:
        throw new IllegalArgumentException("Invalid parameter set: " + parameterSet);
    }
  }

  /**
   * Get the parameter set (512, 768, or 1024) from an ML-KEM key.
   *
   * @param key the ML-KEM key to extract parameter set from
   * @return the parameter set (512, 768, or 1024)
   */
  public static int getParameterSet(EvpKemKey key) {
    return key.use(ptr -> nativeGetParameterSet(ptr));
  }

  /**
   * Get private key size for the given parameter set.
   *
   * @param parameterSet ML-KEM parameter set (512, 768, or 1024)
   * @return private key size in bytes
   * @throws IllegalArgumentException if parameter set is invalid
   */
  public static int getPrivateKeySize(int parameterSet) {
    switch (parameterSet) {
      case MLKEM_512:
        return MLKEM512_SECRET_KEY_BYTES;
      case MLKEM_768:
        return MLKEM768_SECRET_KEY_BYTES;
      case MLKEM_1024:
        return MLKEM1024_SECRET_KEY_BYTES;
      default:
        throw new IllegalArgumentException("Invalid parameter set: " + parameterSet);
    }
  }

  /**
   * Get ciphertext size for the given parameter set.
   *
   * @param parameterSet ML-KEM parameter set (512, 768, or 1024)
   * @return ciphertext size in bytes
   * @throws IllegalArgumentException if parameter set is invalid
   */
  public static int getCiphertextSize(int parameterSet) {
    switch (parameterSet) {
      case MLKEM_512:
        return MLKEM512_CIPHERTEXT_BYTES;
      case MLKEM_768:
        return MLKEM768_CIPHERTEXT_BYTES;
      case MLKEM_1024:
        return MLKEM1024_CIPHERTEXT_BYTES;
      default:
        throw new IllegalArgumentException("Invalid parameter set: " + parameterSet);
    }
  }

  /**
   * Validates and extracts the parameter set from an AlgorithmParameterSpec.
   *
   * @param spec the algorithm parameter spec (must not be null)
   * @param key the ML-KEM key to validate against
   * @return the validated parameter set (512, 768, or 1024)
   * @throws InvalidAlgorithmParameterException if spec is null, wrong type, or incompatible with
   *     key
   */
  public static void validateParameterSpec(AlgorithmParameterSpec spec, EvpKemKey key)
      throws InvalidAlgorithmParameterException {

    if (spec == null) {
      throw new InvalidAlgorithmParameterException("Please pass in a non-null parameter spec.");
    }
    if (spec instanceof NamedParameterSpec) {
      NamedParameterSpec namedSpec = (NamedParameterSpec) spec;
      int paramSet = getParameterSet(key);
      String expectedName = "ML-KEM-" + paramSet;

      if (!namedSpec.getName().equals(expectedName)) {
        throw new InvalidAlgorithmParameterException(
            "Parameter spec mismatch. Expected: "
                + expectedName
                + ", but got: "
                + namedSpec.getName());
      }
    } else {
      throw new InvalidAlgorithmParameterException(
          "Unsupported parameter spec type: " + spec.getClass().getName());
    }
  }
}
