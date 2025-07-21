// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

class EvpXECPublicKey extends EvpXECKey implements PublicKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPublicU(long ptr);

  protected transient volatile BigInteger u;

  EvpXECPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpXECPublicKey(final InternalKey key) {
    super(key, true);
  }

  /**
   * Add @Override annotation when this class implements {@link
   * java.security.interfaces.XECPrivateKey} instead of {@link PrivateKey}, when JDK8 support is
   * deprecated and ACCP is built for JDK 11+
   */
  public BigInteger getU() {
    BigInteger result = u;
    if (result == null) {
      synchronized (this) {
        result = u;
        if (result == null) {
          result = nativeBN(EvpXECPublicKey::getPublicU);
          u = result;
        }
      }
    }
    return result;
  }
}
