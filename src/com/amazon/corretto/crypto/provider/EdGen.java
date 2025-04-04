// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class EdGen extends KeyPairGeneratorSpi {
  // Generates a new Ed25519 key and returns a pointer to it encoded as a java |long|
  private static native long generateEvpEdKey();

  private final AmazonCorrettoCryptoProvider provider_;
  private KeyFactory kf;

  EdGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    try {
      kf = KeyFactory.getInstance("EdDSA", "SunEC");
    } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
      // This case indicates that either:
      // 1.) The current JDK runtime version does not support EdDSA (i.e. JDK version <15) or
      // 2.) No SunEC is registered with JCA
      kf = null;
    }
  }

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    final EvpEdPrivateKey privateKey = new EvpEdPrivateKey(generateEvpEdKey());
    final EvpEdPublicKey publicKey = privateKey.getPublicKey();
    if (kf == null) { // This case indicates JDK EdDSA conditions as described in the constructor
      return new KeyPair(publicKey, privateKey);
    }
    try {
      final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKey.getEncoded());
      final PrivateKey jcePrivateKey = kf.generatePrivate(privateKeyPkcs8);
      final PublicKey jcePublicKey = kf.generatePublic(publicKeyX509);
      return new KeyPair(jcePublicKey, jcePrivateKey);
    } catch (final GeneralSecurityException e) {
      throw new RuntimeException("Error generating key pair", e);
    }
  }
}
