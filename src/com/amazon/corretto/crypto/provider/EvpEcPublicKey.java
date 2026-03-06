// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

class EvpEcPublicKey extends EvpEcKey implements ECPublicKey {
  private static final long serialVersionUID = 1;

  private static native void getPublicPointCoords(long ptr, byte[] x, byte[] y);

  protected transient volatile ECPoint w;

  EvpEcPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEcPublicKey(final InternalKey key) {
    super(key, true);
  }

  @Override
  public ECPoint getW() {
    ECPoint result = w;
    if (result == null) {
      synchronized (this) {
        result = w;
        if (result == null) {
          final int fieldSizeBits = getParams().getCurve().getField().getFieldSize();
          final int fieldSizeBytes = (fieldSizeBits + 7) / 8;

          final byte[] x = new byte[fieldSizeBytes];
          final byte[] y = new byte[fieldSizeBytes];

          useVoid(ptr -> getPublicPointCoords(ptr, x, y));

          result = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
          w = result;
        }
      }
    }
    return result;
  }

  @Override
  public String toString() {
    final ECParameterSpec parameterSpec = getParams();
    final ECPoint point = getW();

    final StringBuffer sb = new StringBuffer(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    sb.append(" ");
    sb.append(getAlgorithm());
    sb.append(" public key, ");
    sb.append(parameterSpec.getOrder().bitLength());
    sb.append(" bits\n  public x coord: ");
    sb.append(point.getAffineX());
    sb.append("\n  public y coord: ");
    sb.append(point.getAffineY());
    sb.append("\n  parameters: ").append(parameterSpec);
    return sb.toString();
  }
}
