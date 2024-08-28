// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class CounterKdfSpi extends KdfSpi {
  private final int digestCode;

  CounterKdfSpi(final int digestCode) {
    this.digestCode = digestCode;
  }

  @Override
  protected SecretKey engineGenerateSecret(final KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof CounterKdfSpec)) {
      throw new InvalidKeySpecException("Expected a key spec of type CounterKdfSpec");
    }
    final CounterKdfSpec spec = (CounterKdfSpec) keySpec;

    final byte[] secret = spec.getSecret();

    final byte[] info = spec.getInfo();

    final byte[] output = new byte[spec.getOutputLen()];

    nKdf(digestCode, secret, secret.length, info, info.length, output, output.length);

    return new SecretKeySpec(output, spec.getAlgorithName());
  }

  private static native void nKdf(
      int digestCode,
      byte[] secret,
      int secretLen,
      byte[] info,
      int infoLen,
      byte[] output,
      int outputLen);

  static final Map<String, CounterKdfSpi> INSTANCES = getInstances();

  static final String CTR_KDF_WITH_HMAC_SHA256 = "CounterKdfWithHmacSHA256";
  static final String CTR_KDF_WITH_HMAC_SHA384 = "CounterKdfWithHmacSHA384";
  static final String CTR_KDF_WITH_HMAC_SHA512 = "CounterKdfWithHmacSHA512";

  private static Map<String, CounterKdfSpi> getInstances() {
    final Map<String, CounterKdfSpi> kdfs = new HashMap<>();
    kdfs.put(
        getSpiFactoryForAlgName(CTR_KDF_WITH_HMAC_SHA256), new CounterKdfSpi(Utils.SHA256_CODE));
    kdfs.put(
        getSpiFactoryForAlgName(CTR_KDF_WITH_HMAC_SHA384), new CounterKdfSpi(Utils.SHA384_CODE));
    kdfs.put(
        getSpiFactoryForAlgName(CTR_KDF_WITH_HMAC_SHA512), new CounterKdfSpi(Utils.SHA512_CODE));
    return Collections.unmodifiableMap(kdfs);
  }

  static String getSpiFactoryForAlgName(final String alg) {
    return alg.toUpperCase();
  }
}
