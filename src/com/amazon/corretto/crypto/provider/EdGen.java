// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.InvalidParameterException;

class EdGen extends KeyPairGeneratorSpi {
  /** Generates a new Ed25519 key and returns a pointer to it. */
  private static native long generateEvpEdKey();

  private final AmazonCorrettoCryptoProvider provider_;

  EdGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
  }

  public void initialize(int keysize, SecureRandom random) {
    if (keysize != 255) {
      throw new InvalidParameterException("Params must be Ed25519.");
    }
    return;
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
