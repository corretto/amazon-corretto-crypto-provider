// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

class RsaGen extends KeyPairGeneratorSpi {
  private static final int MIN_KEY_SIZE = Loader.FIPS_BUILD ? 2048 : 512;
  private static final RSAKeyGenParameterSpec DEFAULT_KEYGEN_SPEC =
      new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
  private final KeyFactory keyFactory;
  private final AmazonCorrettoCryptoProvider provider_;
  private RSAKeyGenParameterSpec kgSpec;

  static {
    Loader.load();
  }

  RsaGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    keyFactory = provider_.getKeyFactory(EvpKeyType.RSA);
    kgSpec = DEFAULT_KEYGEN_SPEC;
  }

  private static native long generateEvpKey(int keySize, boolean checkConsistency, byte[] pubExp);

  @Override
  public KeyPair generateKeyPair() {
    final int keySize = kgSpec.getKeysize();

    final byte[] pubExp = kgSpec.getPublicExponent().toByteArray();

    EvpRsaPrivateCrtKey privateKey =
        new EvpRsaPrivateCrtKey(
            generateEvpKey(
                keySize,
                provider_.hasExtraCheck(ExtraCheck.KEY_PAIR_GENERATION_CONSISTENCY),
                pubExp));
    EvpRsaPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }

  @Override
  public void initialize(AlgorithmParameterSpec spec, SecureRandom rnd)
      throws InvalidAlgorithmParameterException {
    if (spec instanceof RSAKeyGenParameterSpec) {
      kgSpec = validateParameter((RSAKeyGenParameterSpec) spec);
    } else {
      throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + spec);
    }
  }

  @Override
  public void initialize(int keysize, SecureRandom rnd) throws InvalidParameterException {
    try {
      kgSpec = validateParameter(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
    } catch (final InvalidAlgorithmParameterException ex) {
      throw new InvalidParameterException(ex.getMessage());
    }
  }

  private static RSAKeyGenParameterSpec validateParameter(final RSAKeyGenParameterSpec spec)
      throws InvalidAlgorithmParameterException {

    // In FIPS mode, ACCP only allows public exponents F4.
    if (Loader.FIPS_BUILD && !RSAKeyGenParameterSpec.F4.equals(spec.getPublicExponent())) {
      throw new InvalidAlgorithmParameterException(
          "For FIPS builds, public exponent must be equal to F4");
    }

    if (spec.getKeysize() < MIN_KEY_SIZE) {
      throw new InvalidAlgorithmParameterException("Unsupported key size: " + spec.getKeysize());
    }

    return spec;
  }
}
