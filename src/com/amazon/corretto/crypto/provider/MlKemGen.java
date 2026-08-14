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
  // target, so it is resolved reflectively. Null only on JDK 10 and older (see the static
  // initializer), where initialize(spec, ...) rejects all specs, which is correct there.
  private static final Class<?> NAMED_PARAMETER_SPEC_CLASS;

  static {
    Class<?> clazz = null;
    try {
      clazz = Class.forName("java.security.spec.NamedParameterSpec");
    } catch (final ClassNotFoundException e) {
      // Absent only on JDK 10 and older. On JDK 11+ the class must exist, so a load failure
      // signals a broken runtime -- fail fast instead of silently disabling spec initialization.
      if (Utils.getJavaVersion() > 10) {
        throw new AssertionError(
            "java.security.spec.NamedParameterSpec must be present on JDK 11+", e);
      }
    }
    NAMED_PARAMETER_SPEC_CLASS = clazz;
  }

  private MlKemParameter parameterSet = null;

  /** Generates a new ML-KEM key and returns a pointer to it. */
  private static native long generateEvpMlKemKey(int parameterSet);

  private MlKemGen(MlKemParameter parameterSet) {
    Loader.checkNativeLibraryAvailability();
    Utils.requireNonNull(parameterSet, "MlKemParameter can not be null");
    this.parameterSet = parameterSet;
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  /**
   * Accepts the standard {@code NamedParameterSpec} initialization that JSSE providers (e.g.
   * BouncyCastle's TLS 1.3 stack) and application code perform before {@code generateKeyPair()}.
   * Each {@code MlKemGen} instance is bound to a single parameter set at construction, so any spec
   * naming that same parameter set is a no-op; any other spec is rejected so the JCA can fail over
   * to a provider that supports it rather than this one silently producing the wrong parameter set.
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
    if (!parameterSet.getAlgorithmName().equalsIgnoreCase(name)) {
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
      final Method getName = NAMED_PARAMETER_SPEC_CLASS.getMethod("getName");
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
