// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/**
 * Utility class for ML-KEM native integration and JDK 11+ features (parameter specifications use
 * NamedParameterSpec).
 */
public final class KemUtils {

  private KemUtils() {}

  static native int nativeGetParameterSet(long keyPtr);

  /**
   * Validates and extracts the parameter set from a NamedParameterSpec.
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

      // Get parameter set directly from key
      int paramSet = key.use(ptr -> nativeGetParameterSet(ptr));
      if (paramSet == -1) {
        throw new RuntimeCryptoException("Unknown ML-KEM parameter set");
      }

      MlKemParameter parameter = MlKemParameter.fromParameterSize(paramSet);
      String expectedName = parameter.getAlgorithmName();

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
