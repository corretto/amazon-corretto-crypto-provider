// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/** Generates recipient key pairs bound to an HPKE base-mode suite. */
class HpkeGen extends KeyPairGeneratorSpi {
  // Volatile because initialize() and generateKeyPair() may run on different threads.
  private volatile HpkeSuite suite;

  HpkeGen() {
    Loader.checkNativeLibraryAvailability();
  }

  /**
   * HPKE key sizes are fixed by the suite, so a suite can't be selected by key size. Per the {@code
   * KeyPairGenerator.initialize(int, SecureRandom)} contract, such a request is rejected with
   * {@code InvalidParameterException}. As for ML-KEM, a keysize of -1 is accepted as a no-op.
   */
  @Override
  public void initialize(final int keysize, final SecureRandom random) {
    if (keysize != -1) {
      throw new InvalidParameterException("HPKE key generation requires an HpkeSpec");
    }
  }

  /**
   * Selects the suite for subsequent {@code generateKeyPair()} calls. Accepts {@link HpkeSpec} or
   * JDK 26's {@code javax.crypto.spec.HPKEParameterSpec} for a supported base-mode suite provided
   * by the linked AWS-LC. Info and encapsulation are ignored.
   *
   * <p>The {@code random} parameter is ignored; key generation draws from AWS-LC's DRBG.
   *
   * @throws InvalidAlgorithmParameterException if parameters are missing, unsupported, or name an
   *     unavailable suite; the generator is then uninitialized
   */
  @Override
  public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
      throws InvalidAlgorithmParameterException {
    suite = null;
    final HpkeSpec spec = HpkeSpec.from(params);
    suite = HpkeSuite.require(spec.kem_id(), spec.kdf_id(), spec.aead_id());
  }

  /**
   * Generates an {@link HpkePublicKey} and {@link HpkePrivateKey} bound to the selected suite's
   * KEM, KDF, and AEAD.
   *
   * @throws IllegalStateException if the generator has not been initialized with parameters
   */
  @Override
  public KeyPair generateKeyPair() {
    final HpkeSuite selected = suite;
    if (selected == null) {
      throw new IllegalStateException("HPKE KeyPairGenerator must be initialized with an HpkeSpec");
    }
    final HpkePrivateKey privateKey = HpkePrivateKey.generate(selected);
    return new KeyPair(privateKey.getPublicKey(), privateKey);
  }
}
