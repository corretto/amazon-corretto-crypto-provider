// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class HpkeGen extends KeyPairGeneratorSpi {
  private final AmazonCorrettoCryptoProvider provider_;
  private HpkeParameterSpec spec = null;

  HpkeGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
  }

  /** Generates a new HPKE key and returns a pointer to it. */
  private static native long generateEvpHpkeKemKeyFromSpec(int hpke_kem_id);

  @Override
  public void initialize(final AlgorithmParameterSpec params, final SecureRandom rnd)
      throws InvalidAlgorithmParameterException {
    if (params instanceof HpkeParameterSpec) {
      // TODO: do validation
      spec = (HpkeParameterSpec) params;
    } else {
      throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + spec);
    }
  }

  @Override
  public void initialize(final int keysize, final SecureRandom rnd)
      throws InvalidParameterException {
    throw new InvalidParameterException(
        "Cannot initialize a KEM key with keysize, must use AlgorithmParameterSpec.");
  }

  @Override
  public KeyPair generateKeyPair() {
    if (spec == null) {
      // TODO: support default spec?
      throw new InvalidParameterException("Spec not initialized");
    }
    final EvpHpkePrivateKey privateKey =
        new EvpHpkePrivateKey(generateEvpHpkeKemKeyFromSpec(spec.getKemId()));
    final EvpHpkePublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }
}
