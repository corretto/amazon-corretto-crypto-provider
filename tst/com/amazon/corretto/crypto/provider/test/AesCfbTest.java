// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@DisabledIf("com.amazon.corretto.crypto.provider.test.AesCfbTest#isDisabled")
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCfbTest {
  private static final String ALGORITHM = "AES/CFB/NoPadding";
  private static final int BLOCK_SIZE = 16;
  private static final int KEY_SIZE_128 = 128;
  private static final int KEY_SIZE_256 = 256;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Class<?> SPI_CLASS;

  // TODO: remove this disablement when AWS-LC-FIPS has moved AES CFB EVP_CIPHER to FIPS module
  public static boolean isDisabled() {
    return TestUtil.NATIVE_PROVIDER.isFips() && !TestUtil.NATIVE_PROVIDER.isExperimentalFips();
  }

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.AesCfbSpi");
    } catch (final ClassNotFoundException ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  public void testBasicEncryptDecrypt() throws Exception {
    final byte[] plaintext = "This is a test message for AES CFB mode".getBytes();
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

  @Test
  public void testEncryptDecryptWithUpdate() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final int halfway = plaintext.length / 2;
    encryptCipher.update(plaintext, 0, halfway);
    encryptCipher.update(plaintext, 0, 0); // 0-len update should do nothing
    encryptCipher.init(
        Cipher.ENCRYPT_MODE,
        key,
        ivSpec); // ensure we can re-init in the middle of an update sequence
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
    final byte[] plaintext = "This is a test message for AES CFB mode".getBytes();
    byte[] buffer = Arrays.copyOf(plaintext, plaintext.length);
    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    final SecretKey key = generateKey(KEY_SIZE_128);
    final IvParameterSpec ivSpec = new IvParameterSpec(new byte[BLOCK_SIZE]);

    // One-shot in same buffer
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    assertArrayEquals(plaintext, buffer);

    // Multi-shot in same buffer
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    buffer = Arrays.copyOf(plaintext, plaintext.length);
    cipher.update(buffer, 0, buffer.length / 2, buffer, 0);
    cipher.update(buffer, buffer.length / 2, buffer.length / 2, buffer, buffer.length / 2);
    assertFalse(Arrays.equals(plaintext, buffer));
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    cipher.update(buffer, 0, buffer.length / 2, buffer, 0);
    cipher.update(buffer, buffer.length / 2, buffer.length / 2, buffer, buffer.length / 2);
    assertArrayEquals(plaintext, buffer);
  }

  @Test
  public void testEncryptDecryptWithByteBuffer() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);
    final ByteBuffer ciphertextBuffer = ByteBuffer.allocate(plaintext.length);
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
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Test different input sizes
    for (int size : new int[] {1, 15, 16, 17, 32, 33, 63, 64, 65, 127, 128, 129}) {
      final byte[] plaintext = new byte[size];
      SECURE_RANDOM.nextBytes(plaintext);

      final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
      cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      final byte[] ciphertext = cipher.doFinal(plaintext);
      assertEquals(size, ciphertext.length);
      assertFalse(Arrays.equals(plaintext, ciphertext), "For size: " + size);
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      final byte[] decrypted = cipher.doFinal(ciphertext);

      assertArrayEquals(
          plaintext, decrypted, "Decrypted text should match original plaintext for size " + size);
    }
  }

  @Test
  public void testCompatibilityWithSunJCE() throws Exception {
    final byte[] plaintext = "This is a test message for AES CFB mode compatibility".getBytes();
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Encrypt with SunJCE
    final Cipher sunEncryptCipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
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
    final Cipher sunDecryptCipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    sunDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] sunDecrypted = sunDecryptCipher.doFinal(accpCiphertext);

    assertArrayEquals(plaintext, sunDecrypted, "SunJCE should be able to decrypt ACCP ciphertext");

    assertEquals(sunEncryptCipher.getAlgorithm(), accpEncryptCipher.getAlgorithm());
  }

  @Test
  public void testKnownAnswerVectors() throws Exception {
    // Test vectors from NIST SP 800-38A, section F.3.17 and F.3.18 (CFB128-AES256)
    final byte[] key =
        TestUtil.decodeHex("603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4");
    final byte[] iv = TestUtil.decodeHex("000102030405060708090a0b0c0d0e0f");
    final byte[] plaintext =
        TestUtil.decodeHex(
            "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex(
            "dc7e84bfda79164b7ecd8486985d3860"
                + "39ffed143b28b1c832113c6331e5407b"
                + "df10132415e54b92a13ed0a8267ae2f9"
                + "75a385741ab9cef82031623d55b1e471");

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
  public void testKnownAnswerVectors128() throws Exception {
    // Test vectors from NIST SP 800-38A, section F.3.13 and F.3.14 (CFB128-AES128)
    final byte[] key = TestUtil.decodeHex("2b7e151628aed2a6abf7158809cf4f3c");
    final byte[] iv = TestUtil.decodeHex("000102030405060708090a0b0c0d0e0f");
    final byte[] plaintext =
        TestUtil.decodeHex(
            "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex(
            "3b3fd92eb72dad20333449f8e83cfb4a"
                + "c8a64537a0b3a93fcde3cdad9f1ce58b"
                + "26751f67a3cbb140b1808cf187a4f4df"
                + "c04b05357c5d1c0eeac4c66f9ff7f2e6");

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
  public void testInvalidParameters() throws Throwable {
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
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

    // Test invalid padding
    assertThrows(
        NoSuchPaddingException.class,
        () -> Cipher.getInstance("AES/CFB/InvalidPadding", TestUtil.NATIVE_PROVIDER));

    // Direct invocation via reflection
    Object spi = TestUtil.sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);
    assertThrows(
        NoSuchPaddingException.class,
        () -> TestUtil.sneakyInvoke(spi, "engineSetPadding", "FakePadding"));
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> TestUtil.sneakyInvoke(spi, "engineSetMode", "BadMode"));
  }

  @Test
  public void testMiscellaneous() throws Throwable {
    Object spi = TestUtil.sneakyConstruct(SPI_CLASS.getName(), TestUtil.NATIVE_PROVIDER);
    TestUtil.sneakyInvoke(spi, "engineSetPadding", "NoPadding"); // valid, nothing happens
    TestUtil.sneakyInvoke(spi, "engineSetMode", "CFB"); // valid, nothing happens

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    assertEquals(BLOCK_SIZE, cipher.getBlockSize());

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    assertArrayEquals(iv, cipher.getIV());
    cipher.init(Cipher.ENCRYPT_MODE, key, SECURE_RANDOM);
    assertFalse(
        Arrays.equals(
            iv, cipher.getIV())); // IV gen'd by SECURE_RANDOM should be different from |iv|
    assertArrayEquals( // getIV() and getParameters() should return the same IV value.
        cipher.getIV(), cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV());

    // Same as last test case, but initialized with different signature
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
    parameters.init(cipher.getParameters().getParameterSpec(IvParameterSpec.class));
    cipher.init(Cipher.ENCRYPT_MODE, key, parameters, null);
    assertArrayEquals(
        cipher.getIV(), cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV());

    // We also don't support wrap/unsrap modes (yet?)
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.WRAP_MODE, key, ivSpec, SECURE_RANDOM));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.UNWRAP_MODE, key, ivSpec, SECURE_RANDOM));

    // Only IvParameterSpec is supported
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new RC2ParameterSpec(16), SECURE_RANDOM));

    // No null params
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, (AlgorithmParameters) null, SECURE_RANDOM));

    // Key must be an AES key
    Key rsaKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, rsaKey, ivSpec, SECURE_RANDOM));

    // If cipher is left uninitialized, it should output a random IV
    final Cipher uninitCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    IvParameterSpec specOne = uninitCipher.getParameters().getParameterSpec(IvParameterSpec.class);
    assertEquals(BLOCK_SIZE, specOne.getIV().length);
    IvParameterSpec specTwo = uninitCipher.getParameters().getParameterSpec(IvParameterSpec.class);
    assertFalse(Arrays.equals(specOne.getIV(), specTwo.getIV()));

    // getIV(), however, should return null if cipher is not yet initialized
    assertNull(uninitCipher.getIV());

    // Uninitialized cipher can't be updated or finalized
    assertThrows(IllegalStateException.class, () -> uninitCipher.update(new byte[16]));
    assertThrows(IllegalStateException.class, () -> uninitCipher.doFinal(new byte[16]));
  }

  private SecretKey generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES", TestUtil.NATIVE_PROVIDER);
    keyGen.init(keySize);
    return keyGen.generateKey();
  }
}
