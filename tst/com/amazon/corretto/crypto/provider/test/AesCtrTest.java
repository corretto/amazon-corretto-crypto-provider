// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCtrTest {
  private static final String ALGORITHM = "AES/CTR/NoPadding";
  private static final int BLOCK_SIZE = 16;
  private static final int KEY_SIZE_128 = 128;
  private static final int KEY_SIZE_192 = 192;
  private static final int KEY_SIZE_256 = 256;
  private static final int[] SUPPORTED_KEY_SIZES =
      new int[] {KEY_SIZE_128, KEY_SIZE_192, KEY_SIZE_256};
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

  private static int[] supportedKeySizes() {
    return SUPPORTED_KEY_SIZES;
  }

  @ParameterizedTest
  @MethodSource("supportedKeySizes")
  public void testBasicEncryptDecrypt(final int keySize) throws Exception {
    final byte[] plaintext = "This is a test message for AES CTR mode".getBytes();
    final SecretKey key = generateKey(keySize);
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

  @ParameterizedTest
  @MethodSource("supportedKeySizes")
  public void testEncryptDecryptWithUpdate(final int keySize) throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(keySize);
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

  @ParameterizedTest
  @MethodSource("supportedKeySizes")
  public void testEncryptDecryptSameBuffer(final int keySize) throws Exception {
    final byte[] plaintext = "This is a test message for AES CTR mode".getBytes();
    byte[] buffer = Arrays.copyOf(plaintext, plaintext.length);
    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    final SecretKey key = generateKey(keySize);
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

  /**
   * Per the {@code Cipher} contract, {@code doFinal()} resets the cipher to the state it was in
   * immediately after {@code init()}. For CTR mode that means a second {@code doFinal()} without an
   * intervening {@code init()} re-encrypts under the *same* initial counter rather than continuing
   * where the first call left off — a keystream-reuse hazard inherent to the JCE API and identical
   * in SunJCE, not an ACCP defect. This test pins that behavior rather than validating it.
   */
  @ParameterizedTest
  @MethodSource("supportedKeySizes")
  public void testDoFinalTwiceWithoutReinitReusesCounter(final int keySize) throws Exception {
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final byte[] plaintext = new byte[2 * BLOCK_SIZE + 5];
    SECURE_RANDOM.nextBytes(plaintext);

    final Cipher accpCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    accpCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] accpFirst = accpCipher.doFinal(plaintext);
    final byte[] accpSecond = accpCipher.doFinal(plaintext);

    final Cipher sunJceCipher = Cipher.getInstance(ALGORITHM, Security.getProvider("SunJCE"));
    sunJceCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] sunJceFirst = sunJceCipher.doFinal(plaintext);
    final byte[] sunJceSecond = sunJceCipher.doFinal(plaintext);

    assertArrayEquals(sunJceFirst, accpFirst, "first doFinal call diverged from SunJCE");
    assertArrayEquals(sunJceSecond, accpSecond, "second doFinal call diverged from SunJCE");
    assertArrayEquals(
        accpFirst,
        accpSecond,
        "doFinal without an intervening init should reuse the initial counter, per the JCE"
            + " reset-on-doFinal contract");
  }

  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void testEncryptDecryptWithByteBuffer(
      final int keySize,
      final boolean inputDirect,
      final boolean outputDirect,
      final boolean inputReadOnly)
      throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

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

  /** Exercises {@code Cipher.update(ByteBuffer, ByteBuffer)} followed by {@code doFinal}. */
  @ParameterizedTest
  @MethodSource("byteBufferParams")
  public void testEncryptDecryptWithByteBufferUpdate(
      final int keySize,
      final boolean inputDirect,
      final boolean outputDirect,
      final boolean inputReadOnly)
      throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
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

  /**
   * Every combination of input directness, output directness, and input read-only-ness. The
   * input/output directness axes are independent: mixed heap-input/direct-output (and vice versa)
   * exercises paths that a matched pair cannot.
   */
  private static Stream<Arguments> byteBufferParams() {
    // Only testing with a single key size because none of the tested logic should vary based on
    // that.
    return byteBufferMatrix(KEY_SIZE_128);
  }

  /**
   * Verifies correctness when the input/output {@code ByteBuffer}s are views into the middle of
   * larger backing storage: the accessible [position, limit) window neither starts at the beginning
   * nor ends at the end of the backing array/direct buffer. Also verifies that native code
   * reads/writes only within that window, leaving the surrounding padding untouched.
   *
   * <p>The read-only input case is the most interesting one here. A read-only heap buffer reports
   * neither {@code hasArray()} nor {@code isDirect()}, so {@code ShimByteBuffer} copies it into a
   * fresh array and reports {@code offset = 0}, whereas a writable heap buffer is passed through
   * with {@code offset = arrayOffset() + position()}. Combining read-only with a shifted window is
   * therefore the only way to exercise that copy path against a non-zero position.
   */
  @ParameterizedTest
  @MethodSource("byteBufferOffsetParams")
  public void testEncryptDecryptWithByteBufferOffsets(
      final int keySize,
      final boolean inputDirect,
      final boolean outputDirect,
      final boolean inputReadOnly)
      throws Exception {
    final byte[] plaintext = new byte[100];
    SECURE_RANDOM.nextBytes(plaintext);
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final int inPrefix = 7;
    final int inSuffix = 13;
    final int outPrefix = 11;
    final int outSuffix = 5;

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final ByteBuffer plaintextBuffer =
        wrapWithPadding(plaintext, inputDirect, inPrefix, inSuffix, inputReadOnly);
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
        wrapWithPadding(ciphertext, inputDirect, inPrefix, inSuffix, inputReadOnly);
    final ByteBuffer decryptedBuffer =
        allocateWithPadding(ciphertext.length, outputDirect, outPrefix, outSuffix);
    decryptCipher.doFinal(ciphertextInputBuffer, decryptedBuffer);
    assertPaddingIntact(ciphertextInputBuffer, inPrefix, ciphertext.length);
    assertPaddingIntact(decryptedBuffer, outPrefix, ciphertext.length);
    final byte[] decrypted = new byte[ciphertext.length];
    readWindow(decryptedBuffer, outPrefix, decrypted);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  private static Stream<Arguments> byteBufferOffsetParams() {
    return byteBufferMatrix(KEY_SIZE_256);
  }

  /**
   * Cross product of {@code (keySize, inputDirect, outputDirect, inputReadOnly)}. The read-only
   * axis applies to the input only; a read-only output buffer is a misuse case covered separately.
   */
  private static Stream<Arguments> byteBufferMatrix(final int keySize) {
    final List<Arguments> result = new ArrayList<>();
    for (final boolean inputDirect : new boolean[] {false, true}) {
      for (final boolean outputDirect : new boolean[] {false, true}) {
        for (final boolean inputReadOnly : new boolean[] {false, true}) {
          result.add(Arguments.of(keySize, inputDirect, outputDirect, inputReadOnly));
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("inputSizeParams")
  public void testVariousInputSizes(final int keySize, final int size) throws Exception {
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final byte[] plaintext = new byte[size];
    SECURE_RANDOM.nextBytes(plaintext);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = cipher.doFinal(plaintext);
    assertEquals(size, ciphertext.length);
    // Don't do this check on 1-byte plaintext, as it's equal to ciphertext w/ some
    // non-negligible probability when the keystream's single byte is 0.
    if (size > 1) {
      assertFalse(Arrays.equals(plaintext, ciphertext));
    }
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = cipher.doFinal(ciphertext);

    assertArrayEquals(plaintext, decrypted, "Decrypted text should match original plaintext");
  }

  /** Lengths spanning empty-of-a-block, sub-block, exact-block, and block-plus-remainder cases. */
  private static Stream<Arguments> inputSizeParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int size : new int[] {1, 15, 16, 17, 32, 33, 63, 64, 65, 127, 128, 129}) {
      result.add(Arguments.of(KEY_SIZE_256, size));
    }
    return result.stream();
  }

  /**
   * Encrypts with {@code encryptProvider} and decrypts with {@code decryptProvider}, asserting that
   * the round-trip recovers the plaintext. A successful cross-provider round-trip pins the
   * keystream byte-for-byte: any divergence in counter block construction or increment would yield
   * garbage plaintext.
   */
  @ParameterizedTest
  @MethodSource("compatibilityParams")
  public void testCrossProviderCompatibility(
      final int keySize,
      final Provider encryptProvider,
      final Provider decryptProvider,
      final int size)
      throws Exception {
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final byte[] plaintext = new byte[size];
    SECURE_RANDOM.nextBytes(plaintext);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, encryptProvider);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);
    assertEquals(size, ciphertext.length);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, decryptProvider);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArrayEquals(plaintext, decrypted);
    assertEquals(encryptCipher.getAlgorithm(), decryptCipher.getAlgorithm());
  }

  /**
   * Each third-party provider paired against ACCP in both directions, across block-aligned and
   * unaligned lengths.
   *
   * <p>Providers are supplied as {@code Provider} objects rather than by name on purpose: {@link
   * TestUtil#BC_PROVIDER} is constructed directly and never registered via {@code
   * Security.addProvider}, so a name-based lookup of "BC" can return null.
   */
  private static Stream<Arguments> compatibilityParams() {
    final Provider sunJce = Security.getProvider("SunJCE");
    assertNotNull(sunJce, "SunJCE provider is required for cross-provider compatibility tests");

    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : SUPPORTED_KEY_SIZES) {
      for (final Provider other : new Provider[] {sunJce, TestUtil.BC_PROVIDER}) {
        for (final int size : new int[] {1, 15, 16, 17, 64, 100}) {
          result.add(Arguments.of(keySize, other, TestUtil.NATIVE_PROVIDER, size));
          result.add(Arguments.of(keySize, TestUtil.NATIVE_PROVIDER, other, size));
        }
      }
    }
    return result.stream();
  }

  /**
   * Compares ACCP's output byte-for-byte against a counter mode assembled by hand from SunJCE's
   * AES/ECB primitive.
   */
  @ParameterizedTest
  @MethodSource("referenceParams")
  public void testAgainstReferenceImplementation(final int keySize, final int size)
      throws Exception {
    final SecretKey key = generateKey(keySize);
    final byte[] iv = new byte[BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    final byte[] plaintext = new byte[size];
    SECURE_RANDOM.nextBytes(plaintext);
    final byte[] expected = referenceCtr(key, iv, plaintext);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    assertArrayEquals(expected, cipher.doFinal(plaintext), "encryption diverged from reference");

    // CTR is its own inverse, so decrypting the plaintext must produce the same keystream. Checked
    // separately because DECRYPT_MODE takes a different path through the SPI.
    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    assertArrayEquals(expected, cipher.doFinal(plaintext), "decryption diverged from reference");
  }

  private static Stream<Arguments> referenceParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : SUPPORTED_KEY_SIZES) {
      for (final int size : new int[] {1, 15, 16, 17, 32, 33, 63, 64, 65, 127, 128, 129}) {
        result.add(Arguments.of(keySize, size));
      }
    }
    return result.stream();
  }

  /**
   * Pins counter increment behaviour where implementations could plausibly disagree: carry out of
   * the low bytes, and full 128-bit wraparound. Random IVs never reach these cases, so nothing else
   * in this class exercises them.
   *
   * <p>Asserts four-way agreement between ACCP, the ECB-derived reference, SunJCE, and
   * BouncyCastle. Agreement with only the reference would leave open the possibility that the
   * reference encodes the wrong increment semantics; agreement with only one other CTR
   * implementation would not distinguish a shared misreading of SP 800-38A.
   */
  @ParameterizedTest
  @MethodSource("counterEdgeCaseParams")
  public void testCounterCarryAndWraparound(final int keySize, final String ivHex)
      throws Exception {
    final byte[] iv = TestUtil.decodeHex(ivHex);
    assertEquals(BLOCK_SIZE, iv.length, "IV literal must be a full counter block");
    final SecretKey key = generateKey(keySize);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
    // Four blocks, so the carry-affected block is followed by ordinary increments.
    final byte[] plaintext = new byte[4 * BLOCK_SIZE];
    SECURE_RANDOM.nextBytes(plaintext);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, TestUtil.NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = cipher.doFinal(plaintext);

    assertArrayEquals(
        referenceCtr(key, iv, plaintext), ciphertext, "ACCP diverged from the ECB reference");

    for (final Provider other :
        new Provider[] {Security.getProvider("SunJCE"), TestUtil.BC_PROVIDER}) {
      final Cipher otherCipher = Cipher.getInstance(ALGORITHM, other);
      otherCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
      assertArrayEquals(
          otherCipher.doFinal(plaintext), ciphertext, "ACCP diverged from " + other.getName());
    }
  }

  private static Stream<Arguments> counterEdgeCaseParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : SUPPORTED_KEY_SIZES) {
      // Carry out of the low 8 bytes: block 1's counter becomes ...8000000000000000.
      result.add(Arguments.of(keySize, "00000000000000007fffffffffffffff"));
      // Carry confined to the low 4 bytes: block 1 increments byte 11 and clears bytes 12-15.
      result.add(Arguments.of(keySize, "000102030405060708090a0bffffffff"));
      // Full 128-bit wraparound: block 1's counter becomes all zero.
      result.add(Arguments.of(keySize, "ffffffffffffffffffffffffffffffff"));
    }
    return result.stream();
  }

  /**
   * Counter mode built directly on SunJCE's AES/ECB primitive: encrypt each successive counter
   * block and XOR the result into the input. Deliberately uses a different provider and a different
   * primitive from the code under test, so a shared bug is not possible.
   */
  private static byte[] referenceCtr(final SecretKey key, final byte[] iv, final byte[] input)
      throws GeneralSecurityException {
    final Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding", Security.getProvider("SunJCE"));
    ecb.init(Cipher.ENCRYPT_MODE, key);

    final byte[] counter = iv.clone();
    final byte[] output = new byte[input.length];
    for (int offset = 0; offset < input.length; offset += BLOCK_SIZE) {
      final byte[] keystream = ecb.doFinal(counter);
      final int len = Math.min(BLOCK_SIZE, input.length - offset);
      for (int i = 0; i < len; i++) {
        output[offset + i] = (byte) (input[offset + i] ^ keystream[i]);
      }
      incrementCounter(counter);
    }
    return output;
  }

  /**
   * Increments the counter block as a single big-endian 128-bit integer, wrapping to zero on
   * overflow. This is SP 800-38A's standard incrementing function applied to the full block, which
   * is what both AWS-LC's {@code EVP_aes_*_ctr} and SunJCE's {@code CounterMode} implement — as
   * opposed to incrementing only a narrow trailing counter field, which is a property of
   * constructions layered above the primitive (e.g. RFC 3686) rather than of the primitive itself.
   */
  private static void incrementCounter(final byte[] counter) {
    for (int i = counter.length - 1; i >= 0; i--) {
      if (++counter[i] != 0) {
        return; // No carry out of this byte, so higher bytes are unaffected.
      }
    }
  }

  /**
   * Wraps {@code data} in the middle of a larger backing buffer padded with {@link #PADDING_BYTE}
   * on either side, returning a view whose [position, limit) exposes only the {@code data} region.
   * {@code readOnly} views are derived after the window is set, since {@code asReadOnlyBuffer()}
   * preserves position and limit.
   */
  private static ByteBuffer wrapWithPadding(
      final byte[] data,
      final boolean direct,
      final int prefixLen,
      final int suffixLen,
      final boolean readOnly) {
    final byte[] padded = new byte[prefixLen + data.length + suffixLen];
    Arrays.fill(padded, PADDING_BYTE);
    System.arraycopy(data, 0, padded, prefixLen, data.length);
    final ByteBuffer buffer = wrapBuffer(padded, direct);
    buffer.position(prefixLen);
    buffer.limit(prefixLen + data.length);
    return readOnly ? buffer.asReadOnlyBuffer() : buffer;
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
