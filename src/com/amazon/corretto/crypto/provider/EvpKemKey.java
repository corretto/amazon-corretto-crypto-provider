// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public abstract class EvpKemKey extends EvpKey {

  private volatile Integer parameterSet;
  private static final long serialVersionUID = 1;

  private static native int getParameterSet(long ptr);

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.KEM, isPublicKey);
  }

  public int getParameterSet() {
    Integer result = parameterSet;
    if (result == null) {
      synchronized (this) {
        result = parameterSet;
        if (result == null) {
          result = use(ptr -> KemUtils.nativeGetParameterSet(ptr));
          parameterSet = result;
        }
      }
    }
    return result;
  }

  @Override
  public String getAlgorithm() {
    return "ML-KEM-" + getParameterSet();
  }
}
