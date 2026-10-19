// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

abstract class EvpMlDsaKey extends EvpKey {
  private static final long serialVersionUID = 1;

  // Derived lazily from the native key; transient so a deserialized key recomputes it.
  private transient volatile MlDsaParameter parameterSet;

  EvpMlDsaKey(InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.MLDSA, isPublicKey);
  }

  MlDsaParameter getParameterSet() {
    MlDsaParameter result = parameterSet;
    if (result == null) {
      result = MlDsaParameter.fromX509EncodedLength(use(EvpKey::encodePublicKey).length);
      parameterSet = result;
    }
    return result;
  }

  /**
   * Returns a {@code NamedParameterSpec} naming this key's parameter set (e.g. "ML-DSA-65"), or
   * null on JDK 10 and older.
   *
   * <p>On JDK 22+ this overrides {@code AsymmetricKey.getParams()}. The JDK uses it to pick the
   * parameter-set-specific AlgorithmIdentifier when signing (e.g. keytool and jarsigner via {@code
   * SignatureUtil.fromSignature}), since the generic "ML-DSA" signature name has no OID.
   */
  public AlgorithmParameterSpec getParams() {
    return NamedParameterSpecs.newNamedParameterSpec(getParameterSet().getAlgorithmName());
  }
}
