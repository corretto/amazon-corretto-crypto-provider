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

  // Volatile because MlDsaGenGeneric writes it from initialize() while generateKeyPair() reads it;
  // a generator shared between threads could otherwise read a stale parameter set.
  private volatile MlDsaParameter parameterSet;

  private MlDsaGen(final MlDsaParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    Utils.requireNonNull(parameterSet, "MlDsaParameter can not be null");
    this.parameterSet = parameterSet;
  }

  // Sole writer of |parameterSet| after construction. Package-private rather than private because a
  // private member of this class is not inherited by the nested MlDsaGenGeneric subclass.
  final void setParameterSet(final MlDsaParameter selected) {
    this.parameterSet = selected;
  }

  /**
   * Accepts a {@code NamedParameterSpec} naming this generator's own parameter set (a no-op) and
   * rejects any other spec with {@code InvalidAlgorithmParameterException}, so the JCA can fail
   * over rather than this generator silently producing a key of the wrong parameter set. {@link
   * MlDsaGenGeneric} overrides this to make the generic {@code ML-DSA} service selectable, matching
   * ACCP's ML-KEM generators and the SUN provider.
   *
   * <p>The {@code random} parameter is ignored; key generation always draws from AWS-LC's DRBG.
   */
  @Override
  public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
      throws InvalidAlgorithmParameterException {
    final String name = NamedParameterSpecs.requireParameterSetName(params);
    if (!parameterSet.matchesAlgorithmName(name)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported ML-DSA parameter set: "
              + name
              + ". This KeyPairGenerator only supports "
              + parameterSet.getAlgorithmName()
              + ".");
    }
    // Nothing else to configure: generateKeyPair() always produces a |parameterSet| key pair.
  }

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    long pkey_ptr = generateEvpMlDsaKey(parameterSet.getLevel());
    final EvpMlDsaPrivateKey privateKey = new EvpMlDsaPrivateKey(pkey_ptr);
    final EvpMlDsaPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }

  /**
   * Backs the parameter-set-agnostic {@code KeyPairGenerator.ML-DSA} service. Defaults to ML-DSA-44
   * when used without initialization (preserving the historical behavior of this service), but a
   * spec passed to {@code initialize} selects any supported parameter set.
   */
  public static final class MlDsaGenGeneric extends MlDsaGen {
    public MlDsaGenGeneric(AmazonCorrettoCryptoProvider provider) {
      super(MlDsaParameter.MLDSA_44);
    }

    /**
     * Selects the parameter set named by {@code params} (case-insensitively) for subsequent {@code
     * generateKeyPair()} calls, rather than requiring a spec naming ML-DSA-44.
     */
    @Override
    public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
        throws InvalidAlgorithmParameterException {
      final String name = NamedParameterSpecs.requireParameterSetName(params);
      final MlDsaParameter selected = MlDsaParameter.fromAlgorithmName(name);
      if (selected == null) {
        throw new InvalidAlgorithmParameterException(
            "Unsupported ML-DSA parameter set: "
                + name
                + ". Supported parameter sets are "
                + MlDsaParameter.supportedAlgorithmNames()
                + ".");
      }
      setParameterSet(selected);
    }
  }

  public static final class MlDsaGen44 extends MlDsaGen {
    public MlDsaGen44(AmazonCorrettoCryptoProvider provider) {
      super(MlDsaParameter.MLDSA_44);
    }
  }

  public static final class MlDsaGen65 extends MlDsaGen {
    public MlDsaGen65(AmazonCorrettoCryptoProvider provider) {
      super(MlDsaParameter.MLDSA_65);
    }
  }

  public static final class MlDsaGen87 extends MlDsaGen {
    public MlDsaGen87(AmazonCorrettoCryptoProvider provider) {
      super(MlDsaParameter.MLDSA_87);
    }
  }
}
