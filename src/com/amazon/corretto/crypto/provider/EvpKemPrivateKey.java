// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

public class EvpKemPrivateKey extends EvpKemKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  EvpKemPrivateKey(final long ptr, final EvpKeyType type) {
    this(new InternalKey(ptr), type);
  }

  EvpKemPrivateKey(final InternalKey key, final EvpKeyType type) {
    super(key, type, false);
  }

  public EvpKemPublicKey getPublicKey() {
    this.ephemeral = true;
    this.sharedKey = true;
    final EvpKemPublicKey result = new EvpKemPublicKey(internalKey, this.type);
    result.sharedKey = true;
    return result;
  }
}
