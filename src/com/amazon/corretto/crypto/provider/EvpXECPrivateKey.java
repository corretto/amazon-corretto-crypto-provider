// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.security.PrivateKey;
import java.util.Optional;

class EvpXECPrivateKey extends EvpXECKey
    implements PrivateKey, CanDerivePublicKey<EvpXECPublicKey> {

  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateScalar(long ptr);

  protected volatile byte[] scalar;

  EvpXECPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpXECPrivateKey(final InternalKey key) {
    super(key, false);
  }

  @Override
  public EvpXECPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final EvpXECPublicKey result = new EvpXECPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  /**
   * Add @Override annotation when this class implements {@link
   * java.security.interfaces.XECPrivateKey} instead of {@link PrivateKey}, when JDK8 support is
   * deprecated and ACCP is built for JDK 11+
   */
  public Optional<byte[]> getScalar() {
    byte[] result = scalar;
    if (result == null) {
      synchronized (this) {
        result = scalar;
        if (result == null) {
          result = use(EvpXECPrivateKey::getPrivateScalar);
          scalar = result;
        }
      }
    }
    return Optional.ofNullable(result);
  }

  @Override
  protected synchronized void destroyJavaState() {
    super.destroyJavaState();
    scalar = null;
  }
}
