// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

class EdGen extends KeyPairGeneratorSpi {
  /**
   * Generates a new Ed25519 key and returns a pointer to it.
   *
   * @param params a native pointer created by {@link #buildEcParams(int)}
   * @param checkConsistency Run additional consistency checks on the generated keypair
   */
  private static native long generateEvpEdEcKey();

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
    final EvpEdEcPrivateKey privateKey;
    final EvpEdEcPublicKey publicKey;
    privateKey = new EvpEdEcPrivateKey(generateEvpEdEcKey());
    publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }
}
