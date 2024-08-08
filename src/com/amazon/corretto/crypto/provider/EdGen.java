// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

class EdGen extends KeyPairGeneratorSpi {
  /**
   * Generates a new Ed25519 key and returns a pointer to it.
   */
  private static native long generateEvpEdKey();

  private final AmazonCorrettoCryptoProvider provider_;

  EdGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
  }

  public void initialize(int keysize, SecureRandom random) {
    // Has some behavior in Java, but throws error as placeholder for now.
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    final EvpEdPrivateKey privateKey;
    final EvpEdPublicKey publicKey;
    privateKey = new EvpEdPrivateKey(generateEvpEdKey());
    publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }
}
