// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;
import java.util.Optional;

class EvpEdEcPrivateKey extends EvpEdEcKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateKey(long ptr);

  private volatile byte[] privateKey;

  EvpEdEcPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEdEcPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpEdEcPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final EvpEdEcPublicKey result = new EvpEdEcPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  public Optional<byte[]> getBytes() {
    byte[] bytes = privateKey;
    if (bytes == null) {
      synchronized (this) {
        bytes = privateKey;
        if (bytes == null) {
          bytes = use(EvpEdEcPrivateKey::getPrivateKey);
          privateKey = bytes;
        }
      }
    }
    return Optional.ofNullable(bytes);
  }
}
