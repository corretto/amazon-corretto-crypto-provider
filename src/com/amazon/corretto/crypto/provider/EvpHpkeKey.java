// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

class EvpHpkeKey extends EvpKey {
  private static final long serialVersionUID = 1;

  final HpkeParameterSpec spec;

  EvpHpkeKey(final InternalKey key, final boolean isPublicKey, HpkeParameterSpec spec) {
    super(key, EvpKeyType.HPKE, isPublicKey);
    this.spec = spec;
  }

  public HpkeParameterSpec getSpec() {
    return spec;
  }
}
