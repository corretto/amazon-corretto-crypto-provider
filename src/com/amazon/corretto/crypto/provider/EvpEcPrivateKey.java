// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;

class EvpEcPrivateKey extends EvpEcKey implements ECPrivateKey, CanDerivePublicKey<EvpEcPublicKey> {
  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateValue(long ptr);

  protected volatile BigInteger s;

  EvpEcPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEcPrivateKey(final InternalKey key) {
    super(key, false);
  }

  @Override
  public EvpEcPublicKey getPublicKey() {
    // Once our internal key could be elsewhere, we can no longer safely release it when done
    ephemeral = false;
    sharedKey = true;
    final EvpEcPublicKey result = new EvpEcPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  @Override
  public BigInteger getS() {
    BigInteger result = s;
    if (result == null) {
      synchronized (this) {
        result = s;
        if (result == null) {
          result = nativeBN(EvpEcPrivateKey::getPrivateValue);
          s = result;
        }
      }
    }
    return result;
  }

  @Override
  protected synchronized void destroyJavaState() {
    super.destroyJavaState();
    s = null;
  }
}
