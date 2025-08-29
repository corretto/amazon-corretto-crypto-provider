// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public abstract class EvpKemKey extends EvpKey {

  private final MlKemParameter parameterSet;
  private static final long serialVersionUID = 1;

  EvpKemKey(final InternalKey key, final EvpKeyType type, final boolean isPublicKey) {
    super(key, type, isPublicKey);
    this.parameterSet = MlKemParameter.getParameterSet(this.type);
  }

  public MlKemParameter getParameterSet() {
    return parameterSet;
  }
}
