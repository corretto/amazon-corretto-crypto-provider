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

  // Sole writer of |parameterSet| after construction, so the volatile field can stay private. A
  // private member is accessible anywhere in this file but is not inherited, so the nested
  // MlKemGenGeneric subclass could only reach the field as |super.parameterSet|, not
  // |this.parameterSet|.
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
   * Another provider's spec is accepted too when it names its parameter set through a public {@code
   * String getName()}, which is how BouncyCastle's {@code MLKEMParameterSpec} is honored.
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
    final String name = requireParameterSetName(params);
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

  // Extracts the parameter set name |params| designates, rejecting a spec that designates none.
  // Shared with MlKemGenGeneric so both agree on which specs are well-formed.
  private static String requireParameterSetName(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException("params must not be null");
    }
    final String name = getNamedParameter(params);
    if (name == null) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported AlgorithmParameterSpec: " + params.getClass().getName());
    }
    return name;
  }

  // Returns the parameter set name |params| carries, else null. A NamedParameterSpec (or subclass,
  // per SunJCE's instanceof semantics) is read through the accessor resolved at class load.
  private static String getNamedParameter(final AlgorithmParameterSpec params) {
    if (NAMED_PARAMETER_SPEC_CLASS != null && NAMED_PARAMETER_SPEC_CLASS.isInstance(params)) {
      try {
        return (String) NAMED_PARAMETER_SPEC_GET_NAME.invoke(params);
      } catch (final ReflectiveOperationException e) {
        // getName() is a public method on a public JDK type resolved successfully at class load, so
        // a failure here signals a broken runtime rather than an unsupported spec -- fail fast.
        throw new AssertionError("Failed to invoke NamedParameterSpec.getName()", e);
      }
    }
    return getNameFromForeignSpec(params);
  }

  // Some providers name a parameter set with their own spec type, exposing it through the same
  // public getName() accessor. BouncyCastle's MLKEMParameterSpec is the one that matters: its TLS
  // stack initializes KeyPairGenerator.getInstance("ML-KEM") with one, and BC's own generic ML-KEM
  // generator accepts either shape there (see BC's SpecUtil.getNameFrom).
  //
  // Returns null when the name is not readable. Unlike NamedParameterSpec, that means "unsupported
  // spec" rather than a broken runtime, since any spec reaching here belongs to another provider.
  private static String getNameFromForeignSpec(final AlgorithmParameterSpec params) {
    try {
      final Method getName = params.getClass().getMethod("getName");
      if (!String.class.equals(getName.getReturnType())) {
        return null;
      }
      return (String) getName.invoke(params);
    } catch (final ReflectiveOperationException e) {
      return null;
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
      final String name = requireParameterSetName(params);
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
