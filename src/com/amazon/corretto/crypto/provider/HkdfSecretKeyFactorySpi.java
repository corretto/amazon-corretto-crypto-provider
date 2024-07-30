// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.HkdfSpec.HKDF_EXPAND_MODE;
import static com.amazon.corretto.crypto.provider.HkdfSpec.HKDF_EXTRACT_MODE;
import static com.amazon.corretto.crypto.provider.HkdfSpec.HKDF_MODE;
import static com.amazon.corretto.crypto.provider.Utils.getDigestLength;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class HkdfSecretKeyFactorySpi extends KdfSpi {
  private final int digestCode;
  private final int digestLength;

  private HkdfSecretKeyFactorySpi(final int digestCode, final int digestLength) {
    this.digestCode = digestCode;
    this.digestLength = digestLength;
  }

  @Override
  protected SecretKey engineGenerateSecret(final KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof HkdfSpec)) {
      throw new InvalidKeySpecException("KeySpec must be an instance of HkdfSpec");
    }
    final HkdfSpec spec = (HkdfSpec) keySpec;

    final byte[] resultBytes;
    switch (spec.mode) {
      case HKDF_MODE:
        checkExpandLength(spec.desiredLength);
        resultBytes = new byte[spec.desiredLength];
        hkdf(
            resultBytes,
            resultBytes.length,
            digestCode,
            spec.secretOrPrk,
            spec.secretOrPrk.length,
            spec.salt,
            spec.salt.length,
            spec.info,
            spec.info.length);
        break;
      case HKDF_EXTRACT_MODE:
        // In extract mode, we ignore the value of desiredLength and use
        // the output size of the digest as desiredLength
        resultBytes = new byte[digestLength];
        hkdfExtract(
            resultBytes,
            resultBytes.length,
            digestCode,
            spec.secretOrPrk,
            spec.secretOrPrk.length,
            spec.salt,
            spec.salt.length);
        break;
      case HKDF_EXPAND_MODE:
        checkExpandLength(spec.desiredLength);
        resultBytes = new byte[spec.desiredLength];
        hkdfExpand(
            resultBytes,
            resultBytes.length,
            digestCode,
            spec.secretOrPrk,
            spec.secretOrPrk.length,
            spec.info,
            spec.info.length);
        break;
      default:
        throw new AssertionError(
            "This should not be reachable, since the constructor of HkdfSpec ensures the value is"
                + " one of the above choices.");
    }

    return new SecretKeySpec(resultBytes, spec.algorithmName);
  }

  // This check is defined in RFC5869: https://datatracker.ietf.org/doc/html/rfc5869
  // AWS-LC performs this check; however, ACCP also does the check so that the error
  // returned to the user would be more readable.
  private void checkExpandLength(final long outLen) {
    final long upperLimit = ((long) digestLength) * 255L;
    if (outLen >= upperLimit) {
      throw new IllegalArgumentException("Desired output length is too large.");
    }
  }

  private static native void hkdf(
      byte[] jOutput,
      int outputLen,
      int digestCode,
      byte[] jSecret,
      int secretLen,
      byte[] jSalt,
      int saltLen,
      byte[] jInfo,
      int infoLen);

  private static native void hkdfExtract(
      byte[] jOutput,
      int outputLen,
      int digestCode,
      byte[] jSecret,
      int secretLen,
      byte[] jSalt,
      int saltLen);

  private static native void hkdfExpand(
      byte[] jOutput,
      int outputLen,
      int digestCode,
      byte[] jPrk,
      int prkLen,
      byte[] jInfo,
      int infoLen);

  static final Map<String, HkdfSecretKeyFactorySpi> INSTANCES = getInstances();

  private static final String HKDF = "Hkdf";
  private static final String WITH = "With";
  static final String HKDF_WITH_SHA1 = HKDF + WITH + "HmacSHA1";
  static final String HKDF_WITH_SHA256 = HKDF + WITH + "HmacSHA256";
  static final String HKDF_WITH_SHA384 = HKDF + WITH + "HmacSHA384";
  static final String HKDF_WITH_SHA512 = HKDF + WITH + "HmacSHA512";

  private static Map<String, HkdfSecretKeyFactorySpi> getInstances() {
    final Map<String, HkdfSecretKeyFactorySpi> result = new HashMap<>();
    result.put(
        getSpiFactoryForAlgName(HKDF_WITH_SHA1),
        new HkdfSecretKeyFactorySpi(Utils.SHA1_CODE, getDigestLength("sha1")));
    result.put(
        getSpiFactoryForAlgName(HKDF_WITH_SHA256),
        new HkdfSecretKeyFactorySpi(Utils.SHA256_CODE, getDigestLength("sha256")));
    result.put(
        getSpiFactoryForAlgName(HKDF_WITH_SHA384),
        new HkdfSecretKeyFactorySpi(Utils.SHA384_CODE, getDigestLength("sha384")));
    result.put(
        getSpiFactoryForAlgName(HKDF_WITH_SHA512),
        new HkdfSecretKeyFactorySpi(Utils.SHA512_CODE, getDigestLength("sha512")));
    return Collections.unmodifiableMap(result);
  }

  static String getSpiFactoryForAlgName(final String alg) {
    return alg.toUpperCase();
  }
}
