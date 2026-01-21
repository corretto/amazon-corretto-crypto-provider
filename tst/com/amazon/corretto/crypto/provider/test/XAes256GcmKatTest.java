// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@DisabledIf("com.amazon.corretto.crypto.provider.test.XAes256GcmKatTest#isDisabled")
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class XAes256GcmKatTest {
  private static final String ALGORITHM = "XAES_256/GCM/NoPadding";
  private static final int BLOCK_SIZE = 16;
  private static final int IV_SIZE = 24;
  private static final int KEY_SIZE_256 = 256;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Class<?> SPI_CLASS;

  // TODO: remove this disablement when AWS-LC-FIPS has moved AES CFB EVP_CIPHER to FIPS module
  public static boolean isDisabled() {
    return TestUtil.NATIVE_PROVIDER.isFips() && !TestUtil.NATIVE_PROVIDER.isExperimentalFips();
  }

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.XAes256GcmSpi");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  public void testBasicEncryptDecrypt() throws Exception {
    final byte[] plaintext = "This is a test message for XAES_256_GCM mode".getBytes();
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = cipher.doFinal(plaintext);
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = cipher.doFinal(ciphertext);
    assertArrayEquals(plaintext, decrypted);

    // Now do it in place
    SECURE_RANDOM.nextBytes(iv);
    ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final int tag_size = 16;
    final byte[] buffer = Arrays.copyOf(plaintext, plaintext.length + tag_size);
    cipher.doFinal(buffer, 0, plaintext.length, buffer);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertArrayEquals(plaintext, Arrays.copyOf(buffer, buffer.length - tag_size));
  }

  @Test
  public void testEncryptDecryptWithUpdate() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final int halfway = plaintext.length / 2;

    encryptCipher.update(plaintext, 0, 0); // 0-len update should do nothing
    final byte[] firstPart = encryptCipher.update(plaintext, 0, halfway);
    final byte[] secondPart = encryptCipher.doFinal(plaintext, halfway, plaintext.length - halfway);
    final byte[] ciphertext = new byte[firstPart.length + secondPart.length];
    System.arraycopy(firstPart, 0, ciphertext, 0, firstPart.length);
    System.arraycopy(secondPart, 0, ciphertext, firstPart.length, secondPart.length);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] firstDecrypted = decryptCipher.update(ciphertext, 0, 50);
    final byte[] secondDecrypted = decryptCipher.doFinal(ciphertext, 50, ciphertext.length - 50);
    final byte[] decrypted = new byte[firstDecrypted.length + secondDecrypted.length];
    System.arraycopy(firstDecrypted, 0, decrypted, 0, firstDecrypted.length);
    System.arraycopy(secondDecrypted, 0, decrypted, firstDecrypted.length, secondDecrypted.length);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testEncryptDecryptSameBuffer() throws Exception {
    final byte[] plaintext = "This is a test message for XAES_256-GCM mode".getBytes();
    final int tag_size = 16;
    byte[] buffer = Arrays.copyOf(plaintext, plaintext.length + tag_size);
    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    final SecretKey key = generateKey(KEY_SIZE_256);
    IvParameterSpec ivSpec = new IvParameterSpec(new byte[IV_SIZE]);

    // One-shot in same buffer
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length - tag_size, buffer);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertArrayEquals(plaintext, Arrays.copyOf(buffer, buffer.length - tag_size));

    // Multi-shot in same buffer
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    buffer = Arrays.copyOf(plaintext, plaintext.length + tag_size);
    cipher.update(buffer, 0, plaintext.length/4, buffer, 0);
    cipher.update(buffer, plaintext.length/4, plaintext.length/4, buffer, plaintext.length/4);
    cipher.doFinal(buffer, plaintext.length/2, plaintext.length/2, buffer, plaintext.length/2);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer, 0);
    assertArrayEquals(plaintext, Arrays.copyOf(buffer, plaintext.length));
  }

  @Test
  public void testEncryptDecryptWithByteBuffer() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final int tag_size = 16;

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);
    final ByteBuffer ciphertextBuffer = ByteBuffer.allocate(plaintext.length + tag_size);
    encryptCipher.doFinal(plaintextBuffer, ciphertextBuffer);
    ciphertextBuffer.flip();
    final byte[] ciphertext = new byte[ciphertextBuffer.remaining()];
    ciphertextBuffer.get(ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final ByteBuffer decryptedBuffer = ByteBuffer.allocate(ciphertext.length);
    decryptCipher.doFinal(ByteBuffer.wrap(ciphertext), decryptedBuffer);
    decryptedBuffer.flip();
    final byte[] decrypted = new byte[decryptedBuffer.remaining()];
    decryptedBuffer.get(decrypted);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  @Test
  public void testVariousInputSizes() throws Exception {
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final int tag_size = 16;

    // Test different input sizes
    for (int size : new int[] {1, 15, 16, 17, 32, 33, 63, 64, 65, 127, 128, 129}) {
      final byte[] plaintext = new byte[size];
      SECURE_RANDOM.nextBytes(plaintext);

      final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      final byte[] ciphertext = cipher.doFinal(plaintext);
      assertEquals(size + tag_size, ciphertext.length);
      // Don't do this check on 1-byte plaintext, as it's equal to ciphertext w/ some non-negligible
      // probability
      // when the block cipher output's single byte is 0.
      if (size > 1) {
        assertFalse(Arrays.equals(plaintext, ciphertext), "For size: " + size);
      }
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      final byte[] decrypted = cipher.doFinal(ciphertext);

      assertArrayEquals(
          plaintext, decrypted, "Decrypted text should match original plaintext for size " + size);
    }
  }

  @Test
  public void testCompatibilityWithSunJCE() throws Exception {
    final byte[] plaintext =
        "This is a test message for XAES_256_GCM mode compatibility".getBytes();
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Encrypt with SunJCE
    final Cipher sunEncryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    sunEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] sunCiphertext = sunEncryptCipher.doFinal(plaintext);

    // Decrypt with ACCP
    final Cipher accpDecryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    accpDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] accpDecrypted = accpDecryptCipher.doFinal(sunCiphertext);

    assertArrayEquals(plaintext, accpDecrypted, "ACCP should be able to decrypt SunJCE ciphertext");

    // Encrypt with ACCP
    final Cipher accpEncryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    accpEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] accpCiphertext = accpEncryptCipher.doFinal(plaintext);

    // Decrypt with SunJCE
    final Cipher sunDecryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    sunDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] sunDecrypted = sunDecryptCipher.doFinal(accpCiphertext);

    assertArrayEquals(plaintext, sunDecrypted, "SunJCE should be able to decrypt ACCP ciphertext");

    assertEquals(sunEncryptCipher.getAlgorithm(), accpEncryptCipher.getAlgorithm());
  }

  // Source of the following test vectors:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
  @Test
  public void testKnownAnswerVectors0() throws Exception {
    final byte[] key =
        TestUtil.decodeHex("0101010101010101010101010101010101010101010101010101010101010101");
    final byte[] iv = TestUtil.decodeHex("424242424242424242424242424242424242424242424242");
    final byte[] plaintext = TestUtil.decodeHex("48656c6c6f2c20584145532d3235362d47434d21");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex(
            "01e5f78bc99de880bd2eeff2870d361f0eab5b2fc55268f34b14045878fe3668db980319");

    // Test encryption
    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);
    assertArrayEquals(
        expectedCiphertext, ciphertext, "Encryption should match known answer vector");

    // Test decryption
    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(expectedCiphertext);
    assertArrayEquals(plaintext, decrypted, "Decryption should match known answer vector");
  }

  @Test
  public void testKnownAnswerVectors1() throws Exception {
    final byte[] key =
        TestUtil.decodeHex("0101010101010101010101010101010101010101010101010101010101010101");
    final byte[] iv = TestUtil.decodeHex("4142434445464748494a4b4c4d4e4f505152535455565758");
    final byte[] plaintext = TestUtil.decodeHex("584145532d3235362d47434d");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271");

    // Test encryption
    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);
    assertArrayEquals(
        expectedCiphertext, ciphertext, "Encryption should match known answer vector");

    // Test decryption
    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(expectedCiphertext);
    assertArrayEquals(plaintext, decrypted, "Decryption should match known answer vector");
  }

  @Test
  public void testKnownAnswerVectors2() throws Exception {
    final byte[] key =
        TestUtil.decodeHex("0303030303030303030303030303030303030303030303030303030303030303");
    final byte[] iv = TestUtil.decodeHex("4142434445464748494a4b4c4d4e4f505152535455565758");
    final byte[] plaintext = TestUtil.decodeHex("584145532d3235362d47434d");
    final byte[] aad = TestUtil.decodeHex("633273702e6f72672f584145532d3235362d47434d");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d");

    // Test encryption
    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    encryptCipher.updateAAD(aad);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);
    assertArrayEquals(
        expectedCiphertext, ciphertext, "Encryption should match known answer vector");

    // Test decryption
    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    decryptCipher.updateAAD(aad);
    final byte[] decrypted = decryptCipher.doFinal(expectedCiphertext);
    assertArrayEquals(plaintext, decrypted, "Decryption should match known answer vector");
  }

  @Test
  public void testInvalidParameters() throws Throwable {
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[IV_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);

    // Test invalid IV size
    final byte[] shortIv = new byte[BLOCK_SIZE - 1];
    SECURE_RANDOM.nextBytes(shortIv);
    final IvParameterSpec shortIvSpec = new IvParameterSpec(shortIv);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, shortIvSpec),
        "Should throw exception for invalid IV size");
    
    // Test invalid key size
    final byte[] invalidKey = new byte[24]; // 192 bits, not supported
    SECURE_RANDOM.nextBytes(invalidKey);
    final SecretKeySpec invalidKeySpec = new SecretKeySpec(invalidKey, "AES");
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, invalidKeySpec, ivSpec),
        "Should throw exception for invalid key size");
  }

  private SecretKey generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES", TestUtil.NATIVE_PROVIDER);
    keyGen.init(keySize);
    return keyGen.generateKey();
  }
}
