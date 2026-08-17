// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.ByteBuffer;
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
  private static final int KEY_SIZE_256 = 256;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final byte PADDING_BYTE = (byte) 0x5A;
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
    final byte[] plaintext = "This is a test message for AES CTR mode".getBytes();
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

    // heap input, heap output
    roundTripByteBuffer(plaintext, key, ivSpec, false, false, false);
    // direct input, direct output
    roundTripByteBuffer(plaintext, key, ivSpec, true, true, false);
    // read-only heap input, heap output
    roundTripByteBuffer(plaintext, key, ivSpec, false, false, true);
    // read-only direct input, direct output
    roundTripByteBuffer(plaintext, key, ivSpec, true, true, true);
  }

  private void roundTripByteBuffer(
      final byte[] plaintext,
      final SecretKey key,
      final IvParameterSpec ivSpec,
      final boolean inputDirect,
      final boolean outputDirect,
      final boolean inputReadOnly)
      throws Exception {
    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    ByteBuffer plaintextBuffer = wrapBuffer(plaintext, inputDirect);
    if (inputReadOnly) {
      plaintextBuffer = plaintextBuffer.asReadOnlyBuffer();
    }
    final ByteBuffer ciphertextBuffer = allocateBuffer(plaintext.length, outputDirect);
    encryptCipher.doFinal(plaintextBuffer, ciphertextBuffer);
    ciphertextBuffer.flip();
    final byte[] ciphertext = new byte[ciphertextBuffer.remaining()];
    ciphertextBuffer.get(ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    ByteBuffer ciphertextInputBuffer = wrapBuffer(ciphertext, inputDirect);
    if (inputReadOnly) {
      ciphertextInputBuffer = ciphertextInputBuffer.asReadOnlyBuffer();
    }
    final ByteBuffer decryptedBuffer = allocateBuffer(ciphertext.length, outputDirect);
    decryptCipher.doFinal(ciphertextInputBuffer, decryptedBuffer);
    decryptedBuffer.flip();
    final byte[] decrypted = new byte[decryptedBuffer.remaining()];
    decryptedBuffer.get(decrypted);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  @Test
  public void testEncryptDecryptWithByteBufferUpdate() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // heap input, heap output
    splitRoundTripByteBuffer(plaintext, key, ivSpec, false, false, false);
    // direct input, direct output
    splitRoundTripByteBuffer(plaintext, key, ivSpec, true, true, false);
    // read-only heap input, heap output
    splitRoundTripByteBuffer(plaintext, key, ivSpec, false, false, true);
    // read-only direct input, direct output
    splitRoundTripByteBuffer(plaintext, key, ivSpec, true, true, true);
  }

  /** Exercises {@code Cipher.update(ByteBuffer, ByteBuffer)} followed by {@code doFinal}. */
  private void splitRoundTripByteBuffer(
      final byte[] plaintext,
      final SecretKey key,
      final IvParameterSpec ivSpec,
      final boolean inputDirect,
      final boolean outputDirect,
      final boolean inputReadOnly)
      throws Exception {
    final int halfway = plaintext.length / 2;

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    ByteBuffer plaintextBuffer = wrapBuffer(plaintext, inputDirect);
    if (inputReadOnly) {
      plaintextBuffer = plaintextBuffer.asReadOnlyBuffer();
    }
    final ByteBuffer ciphertextBuffer = allocateBuffer(plaintext.length, outputDirect);
    plaintextBuffer.limit(halfway);
    encryptCipher.update(plaintextBuffer, ciphertextBuffer);
    plaintextBuffer.limit(plaintext.length);
    encryptCipher.doFinal(plaintextBuffer, ciphertextBuffer);
    ciphertextBuffer.flip();
    final byte[] ciphertext = new byte[ciphertextBuffer.remaining()];
    ciphertextBuffer.get(ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    ByteBuffer ciphertextInputBuffer = wrapBuffer(ciphertext, inputDirect);
    if (inputReadOnly) {
      ciphertextInputBuffer = ciphertextInputBuffer.asReadOnlyBuffer();
    }
    final ByteBuffer decryptedBuffer = allocateBuffer(ciphertext.length, outputDirect);
    ciphertextInputBuffer.limit(halfway);
    decryptCipher.update(ciphertextInputBuffer, decryptedBuffer);
    ciphertextInputBuffer.limit(ciphertext.length);
    decryptCipher.doFinal(ciphertextInputBuffer, decryptedBuffer);
    decryptedBuffer.flip();
    final byte[] decrypted = new byte[decryptedBuffer.remaining()];
    decryptedBuffer.get(decrypted);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  @Test
  public void testEncryptDecryptWithByteBufferOffsets() throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // heap input, heap output
    offsetRoundTripByteBuffer(plaintext, key, ivSpec, false, false);
    // direct input, direct output
    offsetRoundTripByteBuffer(plaintext, key, ivSpec, true, true);
  }

  /**
   * Verifies correctness when the input/output {@code ByteBuffer}s are views into the middle of
   * larger backing storage: the accessible [position, limit) window neither starts at the beginning
   * nor ends at the end of the backing array/direct buffer. Also verifies that native code
   * reads/writes only within that window, leaving the surrounding padding untouched.
   */
  private void offsetRoundTripByteBuffer(
      final byte[] plaintext,
      final SecretKey key,
      final IvParameterSpec ivSpec,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {
    final int inPrefix = 7;
    final int inSuffix = 13;
    final int outPrefix = 11;
    final int outSuffix = 5;

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final ByteBuffer plaintextBuffer = wrapWithPadding(plaintext, inputDirect, inPrefix, inSuffix);
    final ByteBuffer ciphertextBuffer =
        allocateWithPadding(plaintext.length, outputDirect, outPrefix, outSuffix);
    encryptCipher.doFinal(plaintextBuffer, ciphertextBuffer);
    assertPaddingIntact(plaintextBuffer, inPrefix, plaintext.length);
    assertPaddingIntact(ciphertextBuffer, outPrefix, plaintext.length);
    final byte[] ciphertext = new byte[plaintext.length];
    readWindow(ciphertextBuffer, outPrefix, ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final ByteBuffer ciphertextInputBuffer =
        wrapWithPadding(ciphertext, inputDirect, inPrefix, inSuffix);
    final ByteBuffer decryptedBuffer =
        allocateWithPadding(ciphertext.length, outputDirect, outPrefix, outSuffix);
    decryptCipher.doFinal(ciphertextInputBuffer, decryptedBuffer);
    assertPaddingIntact(ciphertextInputBuffer, inPrefix, ciphertext.length);
    assertPaddingIntact(decryptedBuffer, outPrefix, ciphertext.length);
    final byte[] decrypted = new byte[ciphertext.length];
    readWindow(decryptedBuffer, outPrefix, decrypted);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  /**
   * Wraps {@code data} in the middle of a larger backing buffer padded with {@link #PADDING_BYTE}
   * on either side, returning a view whose [position, limit) exposes only the {@code data} region.
   */
  private static ByteBuffer wrapWithPadding(
      final byte[] data, final boolean direct, final int prefixLen, final int suffixLen) {
    final byte[] padded = new byte[prefixLen + data.length + suffixLen];
    Arrays.fill(padded, PADDING_BYTE);
    System.arraycopy(data, 0, padded, prefixLen, data.length);
    final ByteBuffer buffer = wrapBuffer(padded, direct);
    buffer.position(prefixLen);
    buffer.limit(prefixLen + data.length);
    return buffer;
  }

  /**
   * Allocates a backing buffer of {@code prefixLen + size + suffixLen} bytes filled with {@link
   * #PADDING_BYTE}, returning a view whose [position, limit) exposes only the middle {@code
   * size}-byte region.
   */
  private static ByteBuffer allocateWithPadding(
      final int size, final boolean direct, final int prefixLen, final int suffixLen) {
    final int totalLen = prefixLen + size + suffixLen;
    final ByteBuffer buffer = allocateBuffer(totalLen, direct);
    for (int i = 0; i < totalLen; i++) {
      buffer.put(i, PADDING_BYTE);
    }
    buffer.position(prefixLen);
    buffer.limit(prefixLen + size);
    return buffer;
  }

  /**
   * Asserts that the padding surrounding the [prefixLen, prefixLen + contentLen) window is
   * untouched, regardless of the buffer's current position/limit.
   */
  private static void assertPaddingIntact(
      final ByteBuffer buffer, final int prefixLen, final int contentLen) {
    final ByteBuffer view = buffer.duplicate();
    view.clear();
    for (int i = 0; i < prefixLen; i++) {
      assertEquals(PADDING_BYTE, view.get(i), "prefix padding byte " + i + " was modified");
    }
    final int suffixStart = prefixLen + contentLen;
    for (int i = suffixStart; i < view.capacity(); i++) {
      assertEquals(PADDING_BYTE, view.get(i), "suffix padding byte " + i + " was modified");
    }
  }

  /**
   * Reads the {@code dest.length} bytes at [windowStart, windowStart + dest.length) without
   * disturbing the buffer's own position/limit.
   */
  private static void readWindow(
      final ByteBuffer buffer, final int windowStart, final byte[] dest) {
    final ByteBuffer view = buffer.duplicate();
    view.clear();
    view.position(windowStart);
    view.get(dest);
  }

  private static ByteBuffer wrapBuffer(final byte[] data, final boolean direct) {
    if (!direct) {
      return ByteBuffer.wrap(data);
    }
    final ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
    buffer.put(data);
    buffer.flip();
    return buffer;
  }

  private static ByteBuffer allocateBuffer(final int size, final boolean direct) {
    return direct ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);
  }

  private SecretKey generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES", TestUtil.NATIVE_PROVIDER);
    keyGen.init(keySize);
    return keyGen.generateKey();
  }
}
