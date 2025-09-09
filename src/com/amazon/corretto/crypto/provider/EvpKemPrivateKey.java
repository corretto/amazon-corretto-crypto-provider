// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpKemPrivateKey extends EvpKemKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  EvpKemPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpKemPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpKemPublicKey getPublicKey() {
    this.ephemeral = true;
    this.sharedKey = true;
    final EvpKemPublicKey result = new EvpKemPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }
}
