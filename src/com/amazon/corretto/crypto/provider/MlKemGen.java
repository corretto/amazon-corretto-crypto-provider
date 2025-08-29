// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class MlKemGen extends KeyPairGeneratorSpi {
  private final AmazonCorrettoCryptoProvider provider_;
  private MlKemParameter parameterSet = null;

  /** Generates a new ML-KEM key and returns a pointer to it. */
  private static native long generateEvpMlKemKey(int parameterSet);

  private MlKemGen(AmazonCorrettoCryptoProvider provider, MlKemParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    this.parameterSet = parameterSet;
  }

  MlKemGen(AmazonCorrettoCryptoProvider provider) {
    this(provider, null);
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    if (parameterSet == null) {
      throw new IllegalStateException("Key type not set");
    }
    long pkey_ptr = generateEvpMlKemKey(parameterSet.getParameterSize());
    final EvpKeyType keyType;
    switch (parameterSet) {
      case MLKEM_512:
        keyType = EvpKeyType.MLKEM_512;
        break;
      case MLKEM_768:
        keyType = EvpKeyType.MLKEM_768;
        break;
      case MLKEM_1024:
        keyType = EvpKeyType.MLKEM_1024;
        break;
      default:
        throw new IllegalStateException("Unknown ML-KEM Parameter Set.");
    }

    final EvpKemPrivateKey privateKey = new EvpKemPrivateKey(pkey_ptr, keyType);
    final EvpKemPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }

  public static final class MlKemGen512 extends MlKemGen {
    public MlKemGen512(AmazonCorrettoCryptoProvider provider) {
      super(provider, MlKemParameter.MLKEM_512);
    }
  }

  public static final class MlKemGen768 extends MlKemGen {
    public MlKemGen768(AmazonCorrettoCryptoProvider provider) {
      super(provider, MlKemParameter.MLKEM_768);
    }
  }

  public static final class MlKemGen1024 extends MlKemGen {
    public MlKemGen1024(AmazonCorrettoCryptoProvider provider) {
      super(provider, MlKemParameter.MLKEM_1024);
    }
  }
}
