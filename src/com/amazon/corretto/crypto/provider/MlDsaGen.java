// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class MlDsaGen extends KeyPairGeneratorSpi {
  /** Generates a new ML-DSA key and returns a pointer to it. */
  private static native long generateEvpMlDsaKey(int level);

  private final AmazonCorrettoCryptoProvider provider_;

  /**
   * level_ corresponds to the purported NIST security level for each ML-DSA variant. It uniquely
   * determines which NID is used to request an ML-DSA key. -1 indicates it is uninitialized.
   */
  private int level_ = -1;

  private MlDsaGen(AmazonCorrettoCryptoProvider provider, Integer level) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    level_ = level;
  }

  MlDsaGen(AmazonCorrettoCryptoProvider provider) {
    this(provider, null);
  }

  /**
   * Rejects every spec, since each of these generators is bound to its parameter set at
   * construction. {@code InvalidAlgorithmParameterException} rather than {@code
   * UnsupportedOperationException} because the checked exception is what {@code
   * KeyPairGenerator.Delegate} expects, so the JCA can fail over instead of propagating.
   */
  @Override
  public void initialize(AlgorithmParameterSpec params, final SecureRandom random)
      throws InvalidAlgorithmParameterException {
    throw new InvalidAlgorithmParameterException(
        "ACCP's ML-DSA KeyPairGenerator cannot be initialized with an AlgorithmParameterSpec. Use"
            + " the ML-DSA-44, ML-DSA-65, or ML-DSA-87 service name to select a parameter set.");
  }

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    if (level_ < 0) {
      throw new IllegalStateException("Key type not set");
    }
    long pkey_ptr = generateEvpMlDsaKey(level_);
    final EvpMlDsaPrivateKey privateKey = new EvpMlDsaPrivateKey(pkey_ptr);
    final EvpMlDsaPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }

  public static final class MlDsaGen44 extends MlDsaGen {
    public MlDsaGen44(AmazonCorrettoCryptoProvider provider) {
      super(provider, 2);
    }
  }

  public static final class MlDsaGen65 extends MlDsaGen {
    public MlDsaGen65(AmazonCorrettoCryptoProvider provider) {
      super(provider, 3);
    }
  }

  public static final class MlDsaGen87 extends MlDsaGen {
    public MlDsaGen87(AmazonCorrettoCryptoProvider provider) {
      super(provider, 5);
    }
  }
}
