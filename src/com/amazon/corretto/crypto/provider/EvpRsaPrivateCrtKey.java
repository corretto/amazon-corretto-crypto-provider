// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

class EvpRsaPrivateCrtKey extends EvpRsaPrivateKey
    implements RSAPrivateCrtKey, CanDerivePublicKey<EvpRsaPublicKey> {
  private static final long serialVersionUID = 1;

  protected volatile BigInteger crtCoef;
  protected volatile BigInteger expP;
  protected volatile BigInteger expQ;
  protected volatile BigInteger primeP;
  protected volatile BigInteger primeQ;
  protected volatile BigInteger publicExponent;

  protected static native void getCrtParams(
      long ptr,
      byte[] crtCoefArr,
      byte[] expPArr,
      byte[] expQArr,
      byte[] primePArr,
      byte[] primeQArr,
      byte[] publicExponentArr,
      byte[] privateExponentArr);

  protected static native boolean hasCrtParams(long ptr);

  protected static EvpRsaPrivateKey buildProperKey(long ptr) {
    // Instantly wrap to avoid leaking pointer in case of exception
    // Most will be CRT keys, so we default to that
    EvpRsaPrivateKey result = new EvpRsaPrivateCrtKey(ptr);
    if (!result.use(EvpRsaPrivateCrtKey::hasCrtParams)) {
      result = new EvpRsaPrivateKey(result.internalKey);
    }
    return result;
  }

  EvpRsaPrivateCrtKey(long ptr) {
    super(new InternalKey(ptr));
  }

  @Override
  public EvpRsaPublicKey getPublicKey() {
    // Once our internal key could be elsewhere, we can no longer safely release it when done
    ephemeral = false;
    sharedKey = true;
    final EvpRsaPublicKey result = new EvpRsaPublicKey(internalKey);
    result.sharedKey = true;
    return result;
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

  protected void initBNs() {
    // Since we use privateExponent to indicate that we are initialized it must be set last
    if (privateExponent != null) {
      return;
    }

    synchronized (this) {
      // Since we use privateExponent to indicate that we are initialized it must be set last
      if (privateExponent != null) {
        return;
      }

      // Everything will be no larger than the modulus.
      final BigInteger modulus = getModulus();
      final int byteLength = (modulus.bitLength() + 7) / 8;

      final byte[] crtCoefArr = new byte[byteLength];
      final byte[] expPArr = new byte[byteLength];
      final byte[] expQArr = new byte[byteLength];
      final byte[] primePArr = new byte[byteLength];
      final byte[] primeQArr = new byte[byteLength];
      final byte[] publicExponentArr = new byte[byteLength];
      final byte[] privateExponentArr = new byte[byteLength];

      useVoid(
          p ->
              getCrtParams(
                  p,
                  crtCoefArr,
                  expPArr,
                  expQArr,
                  primePArr,
                  primeQArr,
                  publicExponentArr,
                  privateExponentArr));

      crtCoef = new BigInteger(1, crtCoefArr);
      expP = new BigInteger(1, expPArr);
      expQ = new BigInteger(1, expQArr);
      primeP = new BigInteger(1, primePArr);
      primeQ = new BigInteger(1, primeQArr);
      publicExponent = new BigInteger(1, publicExponentArr);
      // Since we use privateExponent to indicate that we are initialized it must be set last
      privateExponent = new BigInteger(1, privateExponentArr);
    }
  }

  @Override
  public BigInteger getPrivateExponent() {
    initBNs();
    return privateExponent;
  }

  @Override
  public BigInteger getCrtCoefficient() {
    initBNs();
    return crtCoef;
  }

  @Override
  public BigInteger getPrimeExponentP() {
    initBNs();
    return expP;
  }

  @Override
  public BigInteger getPrimeExponentQ() {
    initBNs();
    return expQ;
  }

  @Override
  public BigInteger getPrimeP() {
    initBNs();
    return primeP;
  }

  @Override
  public BigInteger getPrimeQ() {
    initBNs();
    return primeQ;
  }

  @Override
  protected synchronized void destroyJavaState() {
    super.destroyJavaState();
    crtCoef = null;
    expP = null;
    expQ = null;
    primeP = null;
    primeQ = null;
    privateExponent = null;
  }
}
