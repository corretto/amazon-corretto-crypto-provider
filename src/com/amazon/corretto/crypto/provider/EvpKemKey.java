// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

public abstract class EvpKemKey extends EvpKey {

  private final MlKemParameter parameterSet;
  private static final long serialVersionUID = 1;

  private static native int getParameterSet(long ptr);

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.KEM, isPublicKey);
    this.parameterSet = initializeParameterSet();
  }

  private MlKemParameter initializeParameterSet() {
    try {
      Class<?> kemUtilsClass = Class.forName("com.amazon.corretto.crypto.provider.KemUtils");
      java.lang.reflect.Method method =
          kemUtilsClass.getDeclaredMethod("nativeGetParameterSet", long.class);
      method.setAccessible(true);
      Integer paramSetInt = use(ptr -> (Integer) method.invoke(null, ptr));

      if (paramSetInt != null && paramSetInt != -1) {
        return MlKemParameter.fromParameterSize(paramSetInt);
      }
    } catch (ClassNotFoundException e) {
      // KemUtils not available on non-compatible JDK targets - return null
    } catch (Exception e) {
      throw new RuntimeCryptoException("Failed to initialize ML-KEM key", e);
    }
    return null;
  }

  public MlKemParameter getParameterSet() {
    if (parameterSet == null) {
      throw new RuntimeCryptoException(
          "ML-KEM parameter set not available (JDK8 compatibility mode)");
    }
    return parameterSet;
  }

  @Override
  public String getAlgorithm() {
    if (parameterSet == null) {
      return "ML-KEM"; // Generic algorithm name when parameter set unknown
    }
    return parameterSet.getAlgorithmName();
  }
}
