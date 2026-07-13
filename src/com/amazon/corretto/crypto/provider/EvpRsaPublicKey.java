// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

class EvpRsaPublicKey extends EvpRsaKey implements RSAPublicKey {
  private static final long serialVersionUID = 1;

  private volatile BigInteger publicExponent;

  EvpRsaPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpRsaPublicKey(final InternalKey key) {
    super(key, true);
  }

  @Override
  public BigInteger getPublicExponent() {
    BigInteger result = publicExponent;
    if (result == null) {
      synchronized (this) {
        result = publicExponent;
        if (result == null) {
          result = nativeBN(EvpRsaKey::getPublicExponent);
          publicExponent = result;
        }
      }
    }
    return result;
  }

  @Override
  public String toString() {
    final BigInteger modulus = getModulus();

    final StringBuffer sb = new StringBuffer(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    sb.append(" ");
    sb.append(getAlgorithm());
    sb.append(" public key, ");
    sb.append(modulus.bitLength());
    sb.append(" bits\n  params: ");
    sb.append(getParams());
    sb.append("\n  modulus: ");
    sb.append(modulus);
    sb.append("\n  public exponent: ");
    sb.append(getPublicExponent());
    return sb.toString();
  }
}
