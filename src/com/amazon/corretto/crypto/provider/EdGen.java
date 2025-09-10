// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;

class EdGen extends EvpKeyPairGenerator {

  EdGen(AmazonCorrettoCryptoProvider provider) {
    super(provider, EvpKeyType.EdDSA);
  }

  @Override
  protected KeyFactory getKeyFactory() {
    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance(evpKeyType.jceName, "SunEC");
    } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
      // This case indicates that either:
      // 1.) The current JDK runtime version does not support EdDSA (i.e. JDK version <15) or
      // 2.) No SunEC is registered with JCA
    }
    return keyFactory;
  }

  @Override
  protected EvpEdPrivateKey getPrivateKey(long keyPtr) {
    return new EvpEdPrivateKey(keyPtr);
  }

  @Override
  protected EvpEdPublicKey getPublicKey(PrivateKey privateKey) {
    if (privateKey instanceof EvpEdPrivateKey) {
      return ((EvpEdPrivateKey) privateKey).getPublicKey();
    }
    throw new IllegalArgumentException("Private key must be EvpEdPrivateKey");
  }
}
