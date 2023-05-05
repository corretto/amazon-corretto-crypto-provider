// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

class EvpRsaPrivateKey extends EvpRsaKey implements RSAPrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] encodeRsaPrivateKey(long ptr);

  protected volatile BigInteger privateExponent;

  protected static native byte[] getPrivateExponent(long ptr);

  EvpRsaPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpRsaPrivateKey(final InternalKey key) {
    super(key, false);
  }

  @Override
  public BigInteger getPrivateExponent() {
    BigInteger result = privateExponent;
    if (result == null) {
      synchronized (this) {
        result = privateExponent;
        if (result == null) {
          result = nativeBN(EvpRsaPrivateKey::getPrivateExponent);
          privateExponent = result;
        }
      }
    }

    return result;
  }

  @Override
  protected synchronized void destroyJavaState() {
    super.destroyJavaState();
    privateExponent = null;
  }

  @Override
  protected byte[] internalGetEncoded() {
    // RSA private keys in Java may lack CRT parameters and thus need custom serialization
    byte[] result = encoded;
    if (result == null) {
      synchronized (this) {
        result = encoded;
        if (result == null) {
          result = use(EvpRsaPrivateKey::encodeRsaPrivateKey);
          encoded = result;
        }
      }
    }
    return result;
  }
}
