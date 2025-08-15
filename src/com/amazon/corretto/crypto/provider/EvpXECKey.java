// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

abstract class EvpXECKey extends EvpKey {
  private static final long serialVersionUID = 1;

  protected transient volatile AlgorithmParameterSpec params;

  EvpXECKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.XDH, isPublicKey);
  }

  public AlgorithmParameterSpec getParams() {
    AlgorithmParameterSpec result = params;
    if (result == null) {
      synchronized (this) {
        result = params;
        if (result == null) {
          result = nativeParams(AlgorithmParameterSpec.class);
          params = result;
        }
      }
    }
    return result;
  }
}
