// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;
import java.util.Optional;

class EvpEdPrivateKey extends EvpEdKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateKey(long ptr);

  private volatile byte[] privateKey;

  EvpEdPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEdPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpEdPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final EvpEdPublicKey result = new EvpEdPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  public Optional<byte[]> getBytes() {
    byte[] bytes = privateKey;
    if (bytes == null) {
      synchronized (this) {
        bytes = privateKey;
        if (bytes == null) {
          bytes = use(EvpEdPrivateKey::getPrivateKey);
          privateKey = bytes;
        }
      }
    }
    return Optional.ofNullable(bytes);
  }
}
