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

class ConcatenationKdfSpi extends KdfSpi {
  private final int digestCode;
  // Determines if the digest algorithm should be used as backing PRF or the HMAC.
  private final boolean digestAsPrf;

  ConcatenationKdfSpi(final int digestCode, final boolean digestAsPrf) {
    this.digestCode = digestCode;
    this.digestAsPrf = digestAsPrf;
  }

  @Override
  protected SecretKey engineGenerateSecret(final KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof ConcatenationKdfSpec)) {
      throw new InvalidKeySpecException("Expected a key spec of type ConcatenationKdfSpi.");
    }
    final ConcatenationKdfSpec spec = (ConcatenationKdfSpec) keySpec;

    final byte[] output = new byte[spec.getOutputLen()];

    if (digestAsPrf) {
      nSskdfDigest(
          digestCode,
          spec.getSecret(),
          spec.getSecret().length,
          spec.getInfo(),
          spec.getInfo().length,
          output,
          output.length);
    } else {
      nSskdfHmac(
          digestCode,
          spec.getSecret(),
          spec.getSecret().length,
          spec.getInfo(),
          spec.getInfo().length,
          spec.getSalt(),
          spec.getSalt().length,
          output,
          output.length);
    }

    return new SecretKeySpec(output, spec.getAlgorithmName());
  }

  private static native void nSskdfDigest(
      int digestCode,
      byte[] secret,
      int secretLen,
      byte[] info,
      int infoLen,
      byte[] output,
      int outputLen);

  private static native void nSskdfHmac(
      int digestCode,
      byte[] secret,
      int secretLen,
      byte[] info,
      int infoLen,
      byte[] salt,
      int saltLen,
      byte[] output,
      int outputLen);

  static final Map<String, ConcatenationKdfSpi> INSTANCES = getInstances();

  private static final String CKDF = "ConcatenationKdf";
  private static final String WITH = "With";
  static final String CKDF_WITH_SHA256 = CKDF + WITH + "SHA256";
  static final String CKDF_WITH_SHA384 = CKDF + WITH + "SHA384";
  static final String CKDF_WITH_SHA512 = CKDF + WITH + "SHA512";
  static final String CKDF_WITH_HMAC_SHA256 = CKDF + WITH + "HmacSHA256";
  static final String CKDF_WITH_HMAC_SHA512 = CKDF + WITH + "HmacSHA512";

  private static Map<String, ConcatenationKdfSpi> getInstances() {
    final Map<String, ConcatenationKdfSpi> kdfs = new HashMap<>();
    kdfs.put(
        getSpiFactoryForAlgName(CKDF_WITH_SHA256),
        new ConcatenationKdfSpi(Utils.SHA256_CODE, true));
    kdfs.put(
        getSpiFactoryForAlgName(CKDF_WITH_SHA384),
        new ConcatenationKdfSpi(Utils.SHA384_CODE, true));
    kdfs.put(
        getSpiFactoryForAlgName(CKDF_WITH_SHA512),
        new ConcatenationKdfSpi(Utils.SHA512_CODE, true));

    kdfs.put(
        getSpiFactoryForAlgName(CKDF_WITH_HMAC_SHA256),
        new ConcatenationKdfSpi(Utils.SHA256_CODE, false));
    kdfs.put(
        getSpiFactoryForAlgName(CKDF_WITH_HMAC_SHA512),
        new ConcatenationKdfSpi(Utils.SHA512_CODE, false));

    return Collections.unmodifiableMap(kdfs);
  }

  static String getSpiFactoryForAlgName(final String alg) {
    return alg.toUpperCase();
  }
}
