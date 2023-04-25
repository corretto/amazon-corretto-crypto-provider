// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class KeyGeneratorTest {

  KeyGenerator getAesKeyGenerator() {
    try {
      return KeyGenerator.getInstance("AES", TestUtil.NATIVE_PROVIDER);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  KeyGenerator getDefaultAesKeyGenerator() {
    try {
      return KeyGenerator.getInstance("AES");
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void givenValidAesKeySize_whenGenerate_expectValidSecretKey() {
    Stream.of(128, 192, 256)
        .forEach(
            i -> {
              final KeyGenerator keyGenerator = getAesKeyGenerator();
              keyGenerator.init(i);
              final SecretKey secretKey = keyGenerator.generateKey();
              assertTrue(secretKey instanceof SecretKeySpec);
              assertEquals("AES", secretKey.getAlgorithm());
              assertEquals(i / 8, secretKey.getEncoded().length);
              assertEquals("RAW", secretKey.getFormat());
            });
  }

  @Test
  public void compatibleWithDefaultKeyGen() {
    Stream.of(128, 192, 256)
        .forEach(
            i -> {
              final KeyGenerator keyGenerator = getAesKeyGenerator();
              keyGenerator.init(i);
              final SecretKey secretKey = keyGenerator.generateKey();

              final KeyGenerator defaultKeyGenerator = getDefaultAesKeyGenerator();
              defaultKeyGenerator.init(i);
              final SecretKey secretKeyDefault = defaultKeyGenerator.generateKey();

              assertEquals(secretKeyDefault.getAlgorithm(), secretKey.getAlgorithm());
              assertEquals(secretKeyDefault.getEncoded().length, secretKey.getEncoded().length);
              assertEquals(secretKeyDefault.getFormat(), secretKey.getFormat());
            });
  }

  @Test
  public void givenNullSecureRandom_whenGenerate_expectValidKey() {
    final KeyGenerator keyGenerator = getAesKeyGenerator();
    keyGenerator.init(128, null);
    final SecretKey secretKey = keyGenerator.generateKey();
    assertTrue(secretKey instanceof SecretKeySpec);
    assertEquals("AES", secretKey.getAlgorithm());
    assertEquals(128 / 8, secretKey.getEncoded().length);
  }

  @Test
  public void givenNoParam_whenGenerate_expectDefaultKeySize() throws NoSuchAlgorithmException {
    final KeyGenerator keyGenerator = getAesKeyGenerator();
    final SecretKey secretKey = keyGenerator.generateKey();
    assertTrue(secretKey instanceof SecretKeySpec);
    assertEquals("AES", secretKey.getAlgorithm());
    assertEquals(
        Math.min(256, Cipher.getMaxAllowedKeyLength("AES")) / 8, secretKey.getEncoded().length);
  }

  @SuppressWarnings("serial")
  private static class CustomSecureRandom extends SecureRandom {
    public boolean nextBytesInvoked = false;

    @Override
    public void nextBytes(byte[] bytes) {
      nextBytesInvoked = true;
    }
  }

  @Test
  public void givenCustomSecureRandom_whenGenerate_expectNextBytesBeInvoked() {
    final CustomSecureRandom customSecureRandom = new CustomSecureRandom();
    final KeyGenerator keyGenerator = getAesKeyGenerator();
    keyGenerator.init(customSecureRandom);
    assertFalse(customSecureRandom.nextBytesInvoked);
    keyGenerator.generateKey();
    assertTrue(customSecureRandom.nextBytesInvoked);
  }

  @Test
  public void givenInValidAesKeySize_whenGenerate_throwsInvalidParameterException() {
    Stream.of(512, -1)
        .forEach(
            i -> {
              final KeyGenerator keyGenerator = getAesKeyGenerator();
              assertThrows(InvalidParameterException.class, () -> keyGenerator.init(i));
            });
  }

  @Test
  public void givenKeyGenerator_whenInitWithParam_throwsInvalidAlgorithmParameterException() {
    final KeyGenerator keyGenerator = getAesKeyGenerator();
    assertThrows(InvalidAlgorithmParameterException.class, () -> keyGenerator.init(null, null));
  }
}
