// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class Pbkdf2SecretKeyFactorySpi extends KdfSpi {

  private final int digestCode;
  private final String algorithmName;

  private Pbkdf2SecretKeyFactorySpi(final int digestCode, final String algorithmName) {
    this.digestCode = digestCode;
    this.algorithmName = algorithmName;
  }

  private static native void pbkdf2(
      byte[] jPassword,
      int passwordLen,
      byte[] jSalt,
      int saltLen,
      int iterations,
      int digestCode,
      byte[] jOutput,
      int outputLen);

  @Override
  protected SecretKey engineGenerateSecret(final KeySpec keySpec) throws InvalidKeySpecException {
    if (!(keySpec instanceof PBEKeySpec)) {
      throw new InvalidKeySpecException("KeySpec must be an instance of PBEKeySpec");
    }

    final PBEKeySpec spec = (PBEKeySpec) keySpec;
    final byte[] salt = spec.getSalt();
    final int iterations = spec.getIterationCount();
    final int keyLengthBits = spec.getKeyLength();

    if (salt == null) {
      throw new InvalidKeySpecException("Salt cannot be null");
    }
    if (keyLengthBits <= 0) {
      throw new InvalidKeySpecException("Positive key length required");
    }

    final char[] password = spec.getPassword();
    final byte[] passwordBytes = charsToBytes(password);
    final byte[] derivedKey = new byte[keyLengthBits / 8];

    try {
      pbkdf2(
          passwordBytes,
          passwordBytes.length,
          salt,
          salt.length,
          iterations,
          digestCode,
          derivedKey,
          derivedKey.length);
      return new SecretKeySpec(derivedKey, algorithmName);
    } finally {
      Arrays.fill(password, '\0');
      Arrays.fill(passwordBytes, (byte) 0);
      Arrays.fill(derivedKey, (byte) 0);
    }
  }

  // PBKDF2 takes the password as a byte string, but PBEKeySpec holds
  // it as a char array, so we must convert to bytes before calling into PBKDF2. We use
  // UTF-8 to match SunJCE so keys are identical across providers for any PBEKeySpec input.
  // https://github.com/openjdk/jdk/blob/a73eca9e8b1b96925b4b4d4ccfeffe9891fd8ce1/src/java.base/share/classes/com/sun/crypto/provider/PBKDF2KeyImpl.java#L48-L57
  private static byte[] charsToBytes(final char[] password) {
    final ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    final int len = bb.limit();
    final byte[] passwordBytes = new byte[len];
    bb.get(passwordBytes, 0, len);
    Arrays.fill(bb.array(), bb.arrayOffset(), bb.arrayOffset() + bb.capacity(), (byte) 0);
    return passwordBytes;
  }

  static final Map<String, Pbkdf2SecretKeyFactorySpi> INSTANCES = getInstances();

  private static final String PBKDF2_PREFIX = "PBKDF2WithHmac";
  static final String PBKDF2_WITH_SHA1 = PBKDF2_PREFIX + "SHA1";
  static final String PBKDF2_WITH_SHA224 = PBKDF2_PREFIX + "SHA224";
  static final String PBKDF2_WITH_SHA256 = PBKDF2_PREFIX + "SHA256";
  static final String PBKDF2_WITH_SHA384 = PBKDF2_PREFIX + "SHA384";
  static final String PBKDF2_WITH_SHA512 = PBKDF2_PREFIX + "SHA512";

  private static Map<String, Pbkdf2SecretKeyFactorySpi> getInstances() {
    final Map<String, Pbkdf2SecretKeyFactorySpi> result = new HashMap<>();
    result.put(
        getSpiFactoryForAlgName(PBKDF2_WITH_SHA1),
        new Pbkdf2SecretKeyFactorySpi(Utils.SHA1_CODE, PBKDF2_WITH_SHA1));
    result.put(
        getSpiFactoryForAlgName(PBKDF2_WITH_SHA224),
        new Pbkdf2SecretKeyFactorySpi(Utils.SHA224_CODE, PBKDF2_WITH_SHA224));
    result.put(
        getSpiFactoryForAlgName(PBKDF2_WITH_SHA256),
        new Pbkdf2SecretKeyFactorySpi(Utils.SHA256_CODE, PBKDF2_WITH_SHA256));
    result.put(
        getSpiFactoryForAlgName(PBKDF2_WITH_SHA384),
        new Pbkdf2SecretKeyFactorySpi(Utils.SHA384_CODE, PBKDF2_WITH_SHA384));
    result.put(
        getSpiFactoryForAlgName(PBKDF2_WITH_SHA512),
        new Pbkdf2SecretKeyFactorySpi(Utils.SHA512_CODE, PBKDF2_WITH_SHA512));
    return Collections.unmodifiableMap(result);
  }

  static String getSpiFactoryForAlgName(final String alg) {
    return alg.toUpperCase();
  }
}
