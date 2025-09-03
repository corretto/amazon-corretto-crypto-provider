// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public abstract class EvpKemKey extends EvpKey {

  private final MlKemParameter parameterSet;
  private static final long serialVersionUID = 1;

  private static native int getKeySize(long ptr);

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.MLKEM, isPublicKey);
    int keySize = key.use(EvpKemKey::getKeySize);
    this.parameterSet = MlKemParameter.fromKeySize(keySize);
  }

  private static MlKemParameter determineParameterSetFromKey(long ptr) {
    int keySize = getKeySize(ptr);
    return MlKemParameter.fromKeySize(keySize);
  }

  public MlKemParameter getParameterSet() {
    return parameterSet;
  }

  @Override
  public String getAlgorithm() {
    return parameterSet.getAlgorithmName();
  }
}
