// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Reflective access to {@code java.security.spec.NamedParameterSpec}, shared by the ML-KEM and
 * ML-DSA KeyPairGenerators so they agree on which specs are well-formed.
 */
final class NamedParameterSpecs {
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

  private NamedParameterSpecs() {}

  /**
   * Returns a {@code NamedParameterSpec} for {@code name}, or null on JDK 10 and older where the
   * type does not exist.
   */
  static AlgorithmParameterSpec newNamedParameterSpec(final String name) {
    if (NAMED_PARAMETER_SPEC_CLASS == null) {
      return null;
    }
    try {
      return (AlgorithmParameterSpec)
          NAMED_PARAMETER_SPEC_CLASS.getConstructor(String.class).newInstance(name);
    } catch (final ReflectiveOperationException e) {
      // NamedParameterSpec(String) is a public constructor of a public JDK 11+ type, so a failure
      // here signals a broken runtime -- fail fast.
      throw new AssertionError("Failed to construct NamedParameterSpec", e);
    }
  }

  // Extracts the parameter set name |params| designates, rejecting a spec that designates none.
  static String requireParameterSetName(final AlgorithmParameterSpec params)
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
}
