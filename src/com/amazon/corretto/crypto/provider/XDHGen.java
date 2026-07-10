// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class XDHGen extends EvpKeyPairGenerator {

  // The only XDH curve ACCP supports natively is X25519. This is the standard curve name carried by
  // java.security.spec.NamedParameterSpec.X25519, which JSSE passes when initializing the XDH
  // KeyPairGenerator for the TLS 1.3 handshake.
  private static final String X25519_CURVE_NAME = "X25519";

  XDHGen(AmazonCorrettoCryptoProvider provider) {
    super(provider, EvpKeyType.XDH);
  }

  /**
   * Accepts the standard {@code NamedParameterSpec} initialization used by JSSE (and application
   * code) for X25519. ACCP always generates X25519 XDH keys, so any spec naming the X25519 curve is
   * a no-op; any other spec (e.g. X448) is rejected so the JCA can fail over to a provider that
   * supports it rather than silently producing an X25519 key.
   *
   * <p>{@code NamedParameterSpec} was introduced in JDK 11, but ACCP's main sources are compiled for
   * an older bytecode target, so the spec's curve name is read reflectively rather than by importing
   * the type directly.
   */
  @Override
  public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException("params must not be null");
    }
    final String curveName = getNamedCurve(params);
    if (curveName == null) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported AlgorithmParameterSpec: " + params.getClass().getName());
    }
    if (!X25519_CURVE_NAME.equalsIgnoreCase(curveName)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported curve: " + curveName + ". ACCP's XDH only supports X25519.");
    }
    // Nothing else to configure: generateKeyPair() always produces an X25519 key pair.
  }

  // Returns the curve name if |params| is a java.security.spec.NamedParameterSpec, else null.
  // Uses reflection because NamedParameterSpec is a JDK 11+ type not available at our bytecode
  // target. shouldRegisterX25519 already gates this SPI to JDK 11+, so the type is present at
  // runtime whenever this method is reachable.
  private static String getNamedCurve(final AlgorithmParameterSpec params) {
    if (!"java.security.spec.NamedParameterSpec".equals(params.getClass().getName())) {
      return null;
    }
    try {
      final Method getName = params.getClass().getMethod("getName");
      return (String) getName.invoke(params);
    } catch (final ReflectiveOperationException e) {
      return null;
    }
  }

  @Override
  protected KeyFactory getKeyFactory() {
    KeyFactory keyFactory = null;
    try {
      /* Though XEC keys were introduced in JDK11, while checking key size against the spec parameters,
       * JDK 11 XDHPrivateKeyImpl checks the encoded key which is 34 bytes long
       * and fails the check with message `key length must be 32`
       * https://github.com/openjdk/jdk/blob/jdk-11%2B28/src/jdk.crypto.ec/share/classes/sun/security/ec/XDHPrivateKeyImpl.java#L66
       * whereas JDK12+ checks just the key (octet string) which is 32 bytes long and passes the check as expected
       * https://github.com/openjdk/jdk/blob/jdk-12%2B28/src/jdk.crypto.ec/share/classes/sun/security/ec/XDHPrivateKeyImpl.java#L89
       * So, just for JDK11, keep key factory null to avoid ser/deser in generateKeyPair(), which will fail.
       */
      if (Utils.getJavaVersion() > 11) {
        keyFactory = KeyFactory.getInstance(evpKeyType.jceName, "SunEC");
      }
    } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
      // This case indicates that either:
      // 1.) The current JDK runtime version does not support X25519 (i.e. JDK version <11) or
      // 2.) No SunEC is registered with JCA
    }
    return keyFactory;
  }

  @Override
  protected EvpXECPrivateKey getPrivateKey(long keyPtr) {
    return new EvpXECPrivateKey(keyPtr);
  }

  @Override
  protected EvpXECPublicKey getPublicKey(PrivateKey privateKey) {
    if (privateKey instanceof EvpXECPrivateKey) {
      return ((EvpXECPrivateKey) privateKey).getPublicKey();
    }
    throw new IllegalArgumentException("Private key must be EvpXECPrivateKey");
  }
}
