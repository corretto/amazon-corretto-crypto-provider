// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class MlKemGen extends KeyPairGeneratorSpi {
  // Volatile because MlKemGenGeneric writes it from initialize() while generateKeyPair() reads it;
  // a generator shared between threads could otherwise read a stale parameter set.
  private volatile MlKemParameter parameterSet;

  /** Generates a new ML-KEM key and returns a pointer to it. */
  private static native long generateEvpMlKemKey(int parameterSet);

  private MlKemGen(MlKemParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    Utils.requireNonNull(parameterSet, "MlKemParameter can not be null");
    this.parameterSet = parameterSet;
  }

  // Sole writer of |parameterSet| after construction. Package-private rather than private because a
  // private member of this class is not inherited by the nested MlKemGenGeneric subclass.
  final void setParameterSet(final MlKemParameter selected) {
    this.parameterSet = selected;
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  /**
   * Accepts the standard {@code NamedParameterSpec} initialization that JSSE providers (e.g.
   * BouncyCastle's TLS 1.3 stack) and application code perform before {@code generateKeyPair()}.
   *
   * <p>This parameter-set-specific implementation is bound to its own parameter set at
   * construction, so a spec naming that same parameter set is a no-op and any other spec is
   * rejected with {@code InvalidAlgorithmParameterException}, letting the JCA fail over rather than
   * this one silently producing a key of the wrong parameter set. {@link MlKemGenGeneric} overrides
   * this to make the generic {@code ML-KEM} service selectable instead, mirroring how SunEC treats
   * {@code XDH} versus {@code X25519}/{@code X448}.
   *
   * <p>{@code NamedParameterSpec} was introduced in JDK 11, but ACCP's main sources are compiled
   * for an older bytecode target, so the spec's name is read reflectively rather than by importing
   * the type directly.
   *
   * <p>The {@code random} parameter is ignored; key generation always draws from AWS-LC's DRBG.
   */
  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    final String name = NamedParameterSpecs.requireParameterSetName(params);
    if (!parameterSet.matchesAlgorithmName(name)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported ML-KEM parameter set: "
              + name
              + ". This KeyPairGenerator only supports "
              + parameterSet.getAlgorithmName()
              + ".");
    }
    // Nothing else to configure: generateKeyPair() always produces a |parameterSet| key pair.
  }

  @Override
  public KeyPair generateKeyPair() {
    long pkey_ptr = generateEvpMlKemKey(parameterSet.getParameterSize());

    final EvpKemPrivateKey privateKey = new EvpKemPrivateKey(pkey_ptr);
    final EvpKemPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }

  /**
   * Backs the parameter-set-agnostic {@code KeyPairGenerator.ML-KEM} service. Defaults to
   * ML-KEM-768 when used without initialization (preserving the historical behavior of this
   * service), but a spec passed to {@code initialize} selects any supported parameter set.
   */
  public static final class MlKemGenGeneric extends MlKemGen {
    public MlKemGenGeneric(AmazonCorrettoCryptoProvider provider) {
      super(MlKemParameter.MLKEM_768);
    }

    /**
     * Selects the parameter set named by {@code params} (case-insensitively) for subsequent {@code
     * generateKeyPair()} calls, rather than requiring a spec naming ML-KEM-768.
     */
    @Override
    public void initialize(final AlgorithmParameterSpec params, final SecureRandom random)
        throws InvalidAlgorithmParameterException {
      final String name = NamedParameterSpecs.requireParameterSetName(params);
      final MlKemParameter selected = MlKemParameter.fromAlgorithmName(name);
      if (selected == null) {
        throw new InvalidAlgorithmParameterException(
            "Unsupported ML-KEM parameter set: "
                + name
                + ". Supported parameter sets are "
                + MlKemParameter.supportedAlgorithmNames()
                + ".");
      }
      setParameterSet(selected);
    }
  }

  public static final class MlKemGen512 extends MlKemGen {
    public MlKemGen512(AmazonCorrettoCryptoProvider provider) {
      super(MlKemParameter.MLKEM_512);
    }
  }

  public static final class MlKemGen768 extends MlKemGen {
    public MlKemGen768(AmazonCorrettoCryptoProvider provider) {
      super(MlKemParameter.MLKEM_768);
    }
  }

  public static final class MlKemGen1024 extends MlKemGen {
    public MlKemGen1024(AmazonCorrettoCryptoProvider provider) {
      super(MlKemParameter.MLKEM_1024);
    }
  }
}
