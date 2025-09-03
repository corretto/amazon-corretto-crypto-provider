// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;

class XDHGen extends EvpKeyPairGenerator {

  XDHGen(AmazonCorrettoCryptoProvider provider) {
    super(provider, EvpKeyType.XDH);
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
