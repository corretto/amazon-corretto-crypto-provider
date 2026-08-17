// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCtrTest {
  private static final String ALGORITHM = "AES/CTR/NoPadding";
  private static final int BLOCK_SIZE = 16;
  private static final int KEY_SIZE_128 = 128;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Class<?> SPI_CLASS;

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.AesCtrSpi");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  public void testBasicEncryptDecrypt() throws Exception {
    final byte[] plaintext = "This is a test message for AES CTR mode".getBytes();
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = cipher.doFinal(plaintext);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = cipher.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);

    // Now do it in place
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] buffer = Arrays.copyOf(plaintext, plaintext.length);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertArrayEquals(plaintext, buffer);
  }

  private SecretKey generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES", TestUtil.NATIVE_PROVIDER);
    keyGen.init(keySize);
    return keyGen.generateKey();
  }
}
