// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

abstract class EvpKeyPairGenerator extends KeyPairGeneratorSpi {

  private final AmazonCorrettoCryptoProvider provider_;
  private final KeyFactory kf;

  EvpKeyPairGenerator(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    kf = getKeyFactory();
  }

  // Generates a new EVP key based on the given native Key ID
  // and returns a pointer to it encoded as a java |long|
  protected static native long generateEvpKey(int nativeKeyId);

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  // Provides an appropriate KeyFactory for this key type
  protected abstract KeyFactory getKeyFactory();

  // Invokes similar named native function with appropriate native Key ID
  // to generate a new EVP key of the required type
  protected abstract long generateEvpKey();

  @Override
  public KeyPair generateKeyPair() {
    long keyPtr = generateEvpKey();
    final EvpXECPrivateKey privateKey = new EvpXECPrivateKey(keyPtr);
    final EvpXECPublicKey publicKey = privateKey.getPublicKey();
    if (kf == null) {
      // This case indicates situations where a KeyFactory is not available
      // for this key type due to JDK incompatibility or JCA provider issues.
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
