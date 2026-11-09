// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

abstract class EvpKemKey extends EvpKey {
  private final MlKemParameter parameterSet;
  private static final long serialVersionUID = 1;

  // Determine the key's parameter set based on the key size
  private static native int nativeGetKeySize(long ptr);

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.MLKEM, isPublicKey);
    this.parameterSet = MlKemParameter.fromKeySize(use(EvpKemKey::nativeGetKeySize));
  }

  public MlKemParameter getParameterSet() {
    return parameterSet;
  }

  @Override
  public String getAlgorithm() {
    return parameterSet.getAlgorithmName();
  }

  /**
   * Returns a {@code NamedParameterSpec} naming this key's parameter set (e.g. "ML-KEM-768"), or
   * null on JDK 10 and older.
   *
   * <p>On JDK 22+ this overrides {@code AsymmetricKey.getParams()}, matching the SunJCE provider's
   * ML-KEM keys.
   */
  public AlgorithmParameterSpec getParams() {
    return NamedParameterSpecs.newNamedParameterSpec(parameterSet.getAlgorithmName());
  }
}
