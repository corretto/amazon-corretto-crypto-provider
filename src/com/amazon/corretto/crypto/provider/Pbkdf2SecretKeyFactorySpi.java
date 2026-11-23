// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;

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
    final char[] password = spec.getPassword();
    try {
      return derive(password, spec.getSalt(), spec.getIterationCount(), spec.getKeyLength());
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  @Override
  protected KeySpec engineGetKeySpec(final SecretKey key, final Class<?> keySpec)
      throws InvalidKeySpecException {
    if (!(key instanceof PBEKey)) {
      throw new InvalidKeySpecException("Only PBEKey is accepted");
    }
    // Accept any class a PBEKeySpec can be assigned to, so KeySpec.class works too. Asking
    // instead whether keySpec is a PBEKeySpec would reject it.
    if (keySpec == null || !keySpec.isAssignableFrom(PBEKeySpec.class)) {
      throw new InvalidKeySpecException("Only PBEKeySpec is accepted");
    }

    final PBEKey pbeKey = (PBEKey) key;
    final char[] password = pbeKey.getPassword();
    final byte[] encoded = pbeKey.getEncoded();
    if (encoded == null) {
      throw new InvalidKeySpecException("Key has no encoding");
    }
    try {
      return new PBEKeySpec(
          password, pbeKey.getSalt(), pbeKey.getIterationCount(), encoded.length * 8);
    } catch (final IllegalArgumentException e) {
      throw new InvalidKeySpecException("Invalid key component(s)", e);
    } finally {
      if (password != null) {
        Arrays.fill(password, '\0');
      }
      Arrays.fill(encoded, (byte) 0);
    }
  }

  @Override
  protected SecretKey engineTranslateKey(final SecretKey key) throws InvalidKeyException {
    if (key == null
        || !algorithmName.equalsIgnoreCase(key.getAlgorithm())
        || !"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("Only " + algorithmName + " keys in RAW format are accepted");
    }
    if (key instanceof Pbkdf2Key) {
      return key;
    }
    if (!(key instanceof PBEKey)) {
      throw new InvalidKeyException("Only PBEKey is accepted");
    }

    final PBEKey pbeKey = (PBEKey) key;
    final char[] password = pbeKey.getPassword();
    final byte[] encoded = pbeKey.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("Key has no encoding");
    }
    try {
      // Derive from the foreign key's own components so the result's retained password, salt and
      // iteration count agree with its bytes.
      return derive(password, pbeKey.getSalt(), pbeKey.getIterationCount(), encoded.length * 8);
    } catch (final InvalidKeySpecException e) {
      throw new InvalidKeyException("Invalid key component(s)", e);
    } finally {
      if (password != null) {
        Arrays.fill(password, '\0');
      }
      Arrays.fill(encoded, (byte) 0);
    }
  }

  private Pbkdf2Key derive(
      final char[] password, final byte[] salt, final int iterations, final int keyLengthBits)
      throws InvalidKeySpecException {
    if (salt == null) {
      throw new InvalidKeySpecException("Salt cannot be null");
    }
    if (iterations <= 0) {
      throw new InvalidKeySpecException("Positive iteration count required");
    }
    if (keyLengthBits <= 0) {
      throw new InvalidKeySpecException("Positive key length required");
    }

    // PBEKeySpec normalizes a null password to empty; a foreign PBEKey may still hand us one.
    final char[] pw = password == null ? new char[0] : password;
    final byte[] passwordBytes = charsToBytes(pw);
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
      return new Pbkdf2Key(algorithmName, pw, salt, iterations, derivedKey);
    } finally {
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
