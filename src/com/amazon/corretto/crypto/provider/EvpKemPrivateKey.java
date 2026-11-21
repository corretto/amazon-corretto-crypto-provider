// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpKemPrivateKey extends EvpKemKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] encodeMlKemPrivateKey(long ptr);

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

  @Override
  protected byte[] internalGetEncoded() {
    // ML-KEM private keys prefer seed format, but the FIPS module retains no keygen seed to
    // marshal, so the native encoder falls back to expanded format there. (Mirrors
    // EvpMlDsaPrivateKey's seed/expanded handling.)
    assertNotDestroyed();
    byte[] result = encoded;
    if (result == null) {
      synchronized (this) {
        result = encoded;
        if (result == null) {
          result = use(EvpKemPrivateKey::encodeMlKemPrivateKey);
          encoded = result;
        }
      }
    }
    return result;
  }
}
