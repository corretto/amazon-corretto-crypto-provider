// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public abstract class EvpKemKey extends EvpKey {

  private final MlKemParameter parameterSet;
  private static final long serialVersionUID = 1;

  private static native int getParameterSet(long ptr);

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, MlKemParameter.getEvpKeyTypeFromInternalKey(key), isPublicKey);
    this.parameterSet = MlKemParameter.fromInternalKey(key);
  }

  public MlKemParameter getParameterSet() {
    return parameterSet;
  }

  @Override
  public String getAlgorithm() {
    return parameterSet.getAlgorithmName();
  }
}
