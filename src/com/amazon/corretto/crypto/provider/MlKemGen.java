// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class MlKemGen extends KeyPairGeneratorSpi {
  // java.security.spec.NamedParameterSpec is a JDK 11+ type not available at ACCP's bytecode
  // target, so it and its getName() accessor are resolved reflectively once, here. Both are null
  // only on JDK 10 and older (see the static initializer), where initialize(spec, ...) rejects all
  // specs, which is correct there.
  private static final Class<?> NAMED_PARAMETER_SPEC_CLASS;
  private static final Method NAMED_PARAMETER_SPEC_GET_NAME;

  static {
    Class<?> clazz = null;
    Method getName = null;
    try {
      clazz = Class.forName("java.security.spec.NamedParameterSpec");
      getName = clazz.getMethod("getName");
    } catch (final ClassNotFoundException e) {
      // Absent only on JDK 10 and older. On JDK 11+ the class must exist, so a load failure
      // signals a broken runtime -- fail fast instead of silently disabling spec initialization.
      if (Utils.getJavaVersion() > 10) {
        throw new AssertionError(
            "java.security.spec.NamedParameterSpec must be present on JDK 11+", e);
      }
    } catch (final NoSuchMethodException e) {
      // The class exists but lacks its public getName() accessor -- impossible on a sane JDK 11+.
      throw new AssertionError(
          "java.security.spec.NamedParameterSpec.getName() must be present", e);
    }
    NAMED_PARAMETER_SPEC_CLASS = clazz;
    NAMED_PARAMETER_SPEC_GET_NAME = getName;
  }

  private MlKemParameter parameterSet = null;

  /**
   * True for the parameter-set-agnostic "ML-KEM" service, whose parameter set may be chosen by
   * {@link #initialize(AlgorithmParameterSpec, SecureRandom)}. False for the parameter-set-specific
   * services (ML-KEM-512/768/1024), which are bound at construction and reject any spec naming a
   * different parameter set.
   */
  private final boolean parameterSetSelectable;

  /** Generates a new ML-KEM key and returns a pointer to it. */
  private static native long generateEvpMlKemKey(int parameterSet);

  private MlKemGen(MlKemParameter parameterSet) {
    this(parameterSet, false);
  }

  private MlKemGen(MlKemParameter parameterSet, boolean parameterSetSelectable) {
    Loader.checkNativeLibraryAvailability();
    Utils.requireNonNull(parameterSet, "MlKemParameter can not be null");
    this.parameterSet = parameterSet;
    this.parameterSetSelectable = parameterSetSelectable;
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  /**
   * Accepts the standard {@code NamedParameterSpec} initialization that JSSE providers (e.g.
   * BouncyCastle's TLS 1.3 stack) and application code perform before {@code generateKeyPair()}.
   *
   * <p>Behavior depends on which service this instance came from, mirroring how SunEC treats its
   * generic {@code XDH} service versus its curve-specific {@code X25519}/{@code X448} services:
   *
   * <ul>
   *   <li>the parameter-set-agnostic {@code ML-KEM} service is <em>selectable</em> -- any spec
   *       naming a supported ML-KEM parameter set (case-insensitively) chooses that parameter set
   *       for subsequent {@code generateKeyPair()} calls;
   *   <li>the parameter-set-specific {@code ML-KEM-512/768/1024} services are bound at
   *       construction, so a spec naming that same parameter set is a no-op and any other spec is
   *       rejected with {@code InvalidAlgorithmParameterException}, letting the JCA fail over to a
   *       provider that supports it rather than this one silently producing a key of the wrong
   *       parameter set.
   * </ul>
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
    if (params == null) {
      throw new InvalidAlgorithmParameterException("params must not be null");
    }
    final String name = getNamedParameter(params);
    if (name == null) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported AlgorithmParameterSpec: " + params.getClass().getName());
    }
    if (parameterSetSelectable) {
      final MlKemParameter selected = MlKemParameter.fromAlgorithmName(name);
      if (selected == null) {
        throw new InvalidAlgorithmParameterException(
            "Unsupported ML-KEM parameter set: "
                + name
                + ". Supported parameter sets are ML-KEM-512, ML-KEM-768, and ML-KEM-1024.");
      }
      parameterSet = selected;
      return;
    }
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

  // Returns the parameter set name if |params| is a java.security.spec.NamedParameterSpec (or a
  // subclass, matching SunJCE's instanceof semantics -- NamedParameterSpec is not final), else
  // null.
  private static String getNamedParameter(final AlgorithmParameterSpec params) {
    if (NAMED_PARAMETER_SPEC_CLASS == null || !NAMED_PARAMETER_SPEC_CLASS.isInstance(params)) {
      return null;
    }
    try {
      return (String) NAMED_PARAMETER_SPEC_GET_NAME.invoke(params);
    } catch (final ReflectiveOperationException e) {
      // getName() is a public method on a public JDK type resolved successfully at class load, so a
      // failure here signals a broken runtime rather than an unsupported spec -- fail fast.
      throw new AssertionError("Failed to invoke NamedParameterSpec.getName()", e);
    }
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
   * service), but a {@code NamedParameterSpec} passed to {@code initialize} selects any supported
   * parameter set.
   */
  public static final class MlKemGenGeneric extends MlKemGen {
    public MlKemGenGeneric(AmazonCorrettoCryptoProvider provider) {
      super(MlKemParameter.MLKEM_768, true);
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
