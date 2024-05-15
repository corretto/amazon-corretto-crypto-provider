// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.byteBuffersAreEqual;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genAesKey;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genData;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genIv;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genPattern;
import static com.amazon.corretto.crypto.provider.test.TestUtil.mergeByteBuffers;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArray;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationExplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationImplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.oneShotByteBuffer;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCbcIso10126Test {
  private static final Provider bcProv = new BouncyCastleProvider();

  static Cipher accpCipher() {
    try {
      return Cipher.getInstance("AES/CBC/ISO10126Padding", TestUtil.NATIVE_PROVIDER);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  static Cipher sunCipher() {
    try {
      return Cipher.getInstance("AES/CBC/ISO10126Padding", "SunJCE");
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void emptyCipherTextWithPaddingEnabledShouldProduceEmptyPlaintext() throws Exception {
    // For empty cipher text, SunJCE returns empty plain text when decrypting with padding enabled.
    // This is despite the fact that Cipher text with padding is always at least 16 bytes. This test
    // shows that ACCP is compatible with SunJCE in this manner.
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpCipher();
    final Cipher sun = sunCipher();

    accp.init(Cipher.DECRYPT_MODE, key, iv);
    sun.init(Cipher.DECRYPT_MODE, key, iv);

    final byte[] empty = new byte[0];

    assertEquals(0, accp.doFinal().length);
    assertEquals(sun.doFinal().length, sun.doFinal().length);

    assertEquals(0, accp.doFinal(empty).length);
    assertEquals(sun.doFinal().length, sun.doFinal(empty).length);

    assertNull(accp.update(empty));
    assertEquals(sun.update(empty), sun.update(empty));
    assertEquals(0, accp.doFinal().length);
    assertEquals(sun.doFinal().length, sun.doFinal().length);

    assertNull(accp.update(empty));
    assertEquals(sun.update(empty), sun.update(empty));
    assertEquals(0, accp.doFinal(empty).length);
    assertEquals(sun.doFinal(empty).length, sun.doFinal(empty).length);

    // On the other hand, encrypting an empty array produces 16 bytes of cipher text:
    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertEquals(16, accp.doFinal().length);
    assertEquals(16, sun.doFinal().length);
  }

  @Test
  public void ensureInputEmptyIsResetAfterAnOperation() throws Exception {
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpCipher();

    accp.init(Cipher.ENCRYPT_MODE, key, iv);

    // First we encrypt with a non-empty input.
    assertEquals(16, accp.doFinal(genData(10, 10)).length);
    // Now we decrypt with the same cipher object and empty input:
    accp.init(Cipher.DECRYPT_MODE, key, iv);
    assertEquals(0, accp.doFinal().length);
  }

  @Test
  public void ensureInputEmptyIsResetAfterAnOperationWithBadPaddingToo() throws Exception {
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpCipher();

    accp.init(Cipher.DECRYPT_MODE, key, iv);
    accp.update(new byte[8]);
    // inputIsEmpty is false. We pass bad cipher text to cause bad padding.
    assertThrows(BadPaddingException.class, () -> accp.doFinal(new byte[8]));
    // The cipher must need re-initialization.
    assertThrows(IllegalStateException.class, () -> accp.doFinal());
    // After initialization, inputIsEmpty should be rest to true and produce zero output when
    // decrypting empty input.
    accp.init(Cipher.DECRYPT_MODE, key, iv);
    assertEquals(0, accp.doFinal().length);
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testArrayOneShot(final long seed, final int keySize) throws Exception {
    final byte[] input = genData(seed, (int) seed);
    final SecretKeySpec aesKey = genAesKey(seed + 1, keySize);
    final IvParameterSpec iv = genIv(seed + 2, 16);

    final Cipher accp = accpCipher();
    final Cipher sun = sunCipher();

    accp.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    sun.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] accpCipherText = accp.doFinal(input);
    final byte[] sunCipherText = sun.doFinal(input);
    final int cipherLen = sunCipherText.length;
    assertEquals(cipherLen, accpCipherText.length);
    // Since the padding is random, the last block of the cipher texts are not necessarily the same.
    for (int i = 0; i < accpCipherText.length - 16; i++) {
      assertEquals(sunCipherText[i], accpCipherText[i]);
    }
    // If we use AES/CBC/NoPadding and decrypt both sunCipherText and accpCipherText, then other
    // than the random padding bytes, the rest should be the same:
    final Cipher cbcNoPadding = Cipher.getInstance("AES/CBC/NoPadding", TestUtil.NATIVE_PROVIDER);
    cbcNoPadding.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final byte[] accpUnpaddedPlainText = cbcNoPadding.doFinal(accpCipherText);
    final byte[] sunUnpaddedPlainText = cbcNoPadding.doFinal(sunCipherText);
    assertEquals(cipherLen, accpUnpaddedPlainText.length);
    assertEquals(cipherLen, sunUnpaddedPlainText.length);
    for (int i = 0; i != input.length; i++) {
      assertEquals(input[i], accpUnpaddedPlainText[i]);
      assertEquals(sunUnpaddedPlainText[i], accpUnpaddedPlainText[i]);
    }
    assertEquals(sunUnpaddedPlainText[cipherLen - 1], accpUnpaddedPlainText[cipherLen - 1]);

    accp.init(Cipher.DECRYPT_MODE, aesKey, iv);
    sun.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertArrayEquals(input, accp.doFinal(accpCipherText));
    assertArrayEquals(input, accp.doFinal(sunCipherText));
    assertArrayEquals(input, sun.doFinal(accpCipherText));
  }

  @Test
  public void encryptingSameInputMultipleTimesShouldProduceDifferentCipherTexts() throws Exception {
    final long seed = 100;
    final int keySize = 256;
    final byte[] input = genData(seed, (int) seed);
    final SecretKeySpec aesKey = genAesKey(seed + 1, keySize);
    final IvParameterSpec iv = genIv(seed + 2, 16);

    final Cipher accp = accpCipher();

    accp.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] cipherText1 = accp.doFinal(input);
    final byte[] cipherText2 = accp.doFinal(input);
    assertFalse(Arrays.equals(cipherText1, cipherText2));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testOneShotArrayInPlace(final long seed, final int keySize) throws Exception {
    final int inputLen = (int) seed;
    final Cipher accpCipher = accpCipher();
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int bufferLen = accpCipher.getOutputSize(inputLen);

    final Cipher sunCipher = sunCipher();
    final byte[] inputOutput = genData(seed, bufferLen);
    final byte[] input = Arrays.copyOf(inputOutput, inputLen);
    final ByteBuffer inputByteBuffer = ByteBuffer.wrap(input);

    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(input);
    final int cipherTextLen = accpCipher.doFinal(inputOutput, 0, inputLen, inputOutput, 0);
    assertEquals(sunCipherText.length, cipherTextLen);

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertEquals(inputLen, accpCipher.doFinal(inputOutput, 0, cipherTextLen, inputOutput, 0));
    assertTrue(byteBuffersAreEqual(inputByteBuffer, ByteBuffer.wrap(inputOutput, 0, inputLen)));
    assertEquals(
        inputLen, accpCipher.doFinal(sunCipherText, 0, sunCipherText.length, sunCipherText, 0));
    assertTrue(byteBuffersAreEqual(inputByteBuffer, ByteBuffer.wrap(sunCipherText, 0, inputLen)));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testMultiStepArray(final long seed, final int keySize) throws Exception {
    final int inputLen = (int) seed;
    final Cipher accpCipher = accpCipher();

    final byte[] data = genData(seed, inputLen);
    final ByteBuffer dataByteBuff = ByteBuffer.wrap(data);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunCipher();
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(data);

    for (final List<Integer> processingPattern : processingPatterns) {
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final ByteBuffer accpCipherText = multiStepArray(accpCipher, processingPattern, data);
      assertEquals(sunCipherText.length, accpCipherText.remaining());
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff,
              multiStepArray(
                  accpCipher,
                  processingPattern,
                  accpCipherText.array(),
                  accpCipherText.remaining())));
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff, multiStepArray(accpCipher, processingPattern, sunCipherText)));
    }

    for (final List<Integer> processingPattern : processingPatterns) {
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final ByteBuffer accpCipherTextFromChunks =
          mergeByteBuffers(
              multiStepArrayMultiAllocationImplicit(accpCipher, processingPattern, data));
      assertEquals(sunCipherText.length, accpCipherTextFromChunks.remaining());
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff,
              multiStepArray(
                  accpCipher,
                  processingPattern,
                  accpCipherTextFromChunks.array(),
                  accpCipherTextFromChunks.remaining())));
    }

    for (final List<Integer> processingPattern : processingPatterns) {
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final ByteBuffer accpCipherTextFromChunks =
          mergeByteBuffers(
              multiStepArrayMultiAllocationExplicit(accpCipher, processingPattern, data));
      assertEquals(sunCipherText.length, accpCipherTextFromChunks.remaining());
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff,
              multiStepArray(
                  accpCipher,
                  processingPattern,
                  accpCipherTextFromChunks.array(),
                  accpCipherTextFromChunks.remaining())));
    }
  }

  @Test
  public void testMultiStepArrayOneByteAtATime() throws Exception {
    final long seed = 9854;
    final int keySize = 256;
    final int inputLen = (int) seed;
    final Cipher accpCipher = accpCipher();

    final byte[] data = genData(seed, inputLen);
    final ByteBuffer dataByteBuff = ByteBuffer.wrap(data);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<Integer> oneByteAtATimePattern = genPattern(8788, 1, data.length);

    final Cipher sunCipher = sunCipher();
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(data);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer accpCipherText = multiStepArray(accpCipher, oneByteAtATimePattern, data);
    assertEquals(sunCipherText.length, accpCipherText.remaining());
    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertTrue(
        byteBuffersAreEqual(
            dataByteBuff,
            multiStepArray(
                accpCipher,
                oneByteAtATimePattern,
                accpCipherText.array(),
                accpCipherText.remaining())));
    assertTrue(
        byteBuffersAreEqual(
            dataByteBuff, multiStepArray(accpCipher, oneByteAtATimePattern, sunCipherText)));

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    ByteBuffer accpCipherTextFromChunks =
        mergeByteBuffers(
            multiStepArrayMultiAllocationImplicit(accpCipher, oneByteAtATimePattern, data));
    assertEquals(sunCipherText.length, accpCipherTextFromChunks.remaining());
    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertTrue(
        byteBuffersAreEqual(
            dataByteBuff,
            multiStepArray(
                accpCipher,
                oneByteAtATimePattern,
                accpCipherTextFromChunks.array(),
                accpCipherTextFromChunks.remaining())));

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    accpCipherTextFromChunks =
        mergeByteBuffers(
            multiStepArrayMultiAllocationExplicit(accpCipher, oneByteAtATimePattern, data));
    assertEquals(sunCipherText.length, accpCipherTextFromChunks.remaining());
    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertTrue(
        byteBuffersAreEqual(
            dataByteBuff,
            multiStepArray(
                accpCipher,
                oneByteAtATimePattern,
                accpCipherTextFromChunks.array(),
                accpCipherTextFromChunks.remaining())));
  }

  private static Stream<Arguments> arrayTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128, 192, 256}) {
      for (long seed = 0; seed != 1025; seed++) {
        result.add(Arguments.of(seed, keySize));
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testOneShotByteBuffer(
      final long seed,
      final int keySize,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final int inputLen = (int) seed;

    final Cipher accpCipher = accpCipher();
    final Cipher sunCipher = sunCipher();
    final ByteBuffer input = genData(seed, inputLen, inputDirect);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer accpCipherText =
        genData(seed, accpCipher.getOutputSize(input.remaining()), outputDirect);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int accpOutputLimit = accpCipherText.limit();
    final int accpOutputPosition = accpCipherText.position();
    final ByteBuffer accpInput =
        inputReadOnly ? input.duplicate().asReadOnlyBuffer() : input.duplicate();
    final int accpCipherLen = accpCipher.doFinal(accpInput, accpCipherText);
    // all the input must have been processed.
    assertEquals(0, accpInput.remaining());
    assertEquals(accpInput.limit(), accpInput.position());
    // limit for input should not change
    assertEquals(input.limit(), accpInput.limit());
    // limit should not change for output
    assertEquals(accpOutputLimit, accpCipherText.limit());
    // position of the output should advance by the length of the cipher
    assertEquals(accpOutputPosition + accpCipherLen, accpCipherText.position());

    accpCipherText.flip();

    final ByteBuffer sunInput = input.duplicate();
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, sunInput);
    assertEquals(sunCipherText.remaining(), accpCipherLen);

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertTrue(
        byteBuffersAreEqual(input, oneShotByteBuffer(accpCipher, accpCipherText.duplicate())));
    assertTrue(byteBuffersAreEqual(input, oneShotByteBuffer(accpCipher, sunCipherText)));

    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertTrue(byteBuffersAreEqual(input, oneShotByteBuffer(sunCipher, accpCipherText)));
  }

  private static Stream<Arguments> byteBufferTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (int seed = 0; seed != 1024; seed++) {
        for (final boolean inputReadOnly : new boolean[] {true, false}) {
          for (final boolean inputDirect : new boolean[] {true, false}) {
            for (final boolean outputDirect : new boolean[] {true, false}) {
              result.add(Arguments.of(seed, keySize, inputReadOnly, inputDirect, outputDirect));
            }
          }
        }
      }
    }
    return result.stream();
  }

  @Test
  public void whenBadPaddingDuringDecryptOneShot_expectException() throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec(
            TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            "AES");
    final byte[] input =
        TestUtil.decodeHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031");
    final IvParameterSpec iv =
        new IvParameterSpec(TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F"));
    final Cipher cipher = accpCipher();
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cipher.doFinal(input);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    boolean badPaddingHappened = false;
    for (int i = 0; i < 256; i++) {
      // ISO10126 padding is not a deterministic algorithm. There is chance that we tamper the last
      // byte, but its decrypted value is less than or equal to 16. So we need to try till we
      // succeed.
      cipherText[cipherText.length - 1]++;
      try {
        cipher.doFinal(cipherText);
      } catch (final BadPaddingException e) {
        // This is good. An exception happened.
        badPaddingHappened = true;
        break;
      }
    }
    assertTrue(badPaddingHappened);
    // The cipher will need to be initialized again.
    assertThrows(IllegalStateException.class, () -> cipher.doFinal(cipherText));
  }

  @Test
  public void whenBadPaddingDuringDecryptMultiStep_expectException() throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec(
            TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            "AES");
    final byte[] input =
        TestUtil.decodeHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031");
    final IvParameterSpec iv =
        new IvParameterSpec(TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F"));
    final Cipher cbcPadding = accpCipher();
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cbcPadding.doFinal(input);
    cipherText[cipherText.length - 1] = (byte) (0xFF ^ cipherText[cipherText.length - 1]);
    cbcPadding.init(Cipher.DECRYPT_MODE, key, iv);
    assertDoesNotThrow(() -> cbcPadding.update(cipherText, 0, 16));
    boolean badPaddingHappened = false;
    for (int i = 0; i < 256; i++) {
      // ISO10126 padding is not a deterministic algorithm. There is chance that we tamper the last
      // byte, but its decrypted value is less than or equal to 16. So we need to try till we
      // succeed.
      cipherText[cipherText.length - 1]++;
      try {
        cbcPadding.doFinal(cipherText, 16, cipherText.length - 16);
      } catch (final BadPaddingException e) {
        // This is good. An exception happened.
        badPaddingHappened = true;
        break;
      }
    }
    assertTrue(badPaddingHappened);
    // The cipher will need to be initialized again.
    assertThrows(IllegalStateException.class, () -> cbcPadding.doFinal(cipherText));
  }

  @Test
  public void usingSameKeyIvIsAllowed() throws Exception {
    final SecretKeySpec key = genAesKey(564, 256);
    final IvParameterSpec iv = genIv(644, 16);
    final byte[] input1 = genData(0, 256);
    final byte[] input2 = genData(1, 256);

    final Cipher accp = accpCipher();
    final Cipher sun = sunCipher();

    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertDoesNotThrow(() -> accp.doFinal(input1));
    assertDoesNotThrow(() -> accp.doFinal(input2));
    assertDoesNotThrow(() -> sun.doFinal(input1));
    assertDoesNotThrow(() -> sun.doFinal(input2));

    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertDoesNotThrow(() -> accp.doFinal(input1));
    assertDoesNotThrow(() -> sun.doFinal(input1));
    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertDoesNotThrow(() -> accp.doFinal(input2));
    assertDoesNotThrow(() -> sun.doFinal(input2));
  }

  @ParameterizedTest
  @MethodSource("wrapUnwrapParams")
  public void wrapUnwrapIsCompatibleWithSun(final long seed, final int keySize) throws Exception {
    final int inputLen = (int) seed;
    final String alg = "SECRET_KEY";
    final SecretKeySpec wrappingKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher accp = accpCipher();
    accp.init(Cipher.WRAP_MODE, wrappingKey, iv);
    final Cipher sun = sunCipher();
    sun.init(Cipher.WRAP_MODE, wrappingKey, iv);

    final SecretKeySpec keyToBeWrapped = new SecretKeySpec(genData(seed, inputLen), alg);

    final byte[] sunWrappedKey = sun.wrap(keyToBeWrapped);
    final byte[] accpWrappedKey = accp.wrap(keyToBeWrapped);

    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    sun.init(Cipher.UNWRAP_MODE, wrappingKey, iv);

    final Key sunUnwrappedKey = sun.unwrap(accpWrappedKey, alg, Cipher.SECRET_KEY);
    final Key accpUnwrappedKey1 = accp.unwrap(accpWrappedKey, alg, Cipher.SECRET_KEY);
    final Key accpUnwrappedKey2 = accp.unwrap(sunWrappedKey, alg, Cipher.SECRET_KEY);

    assertEquals(sunUnwrappedKey.getAlgorithm(), accpUnwrappedKey1.getAlgorithm());
    assertEquals(sunUnwrappedKey.getFormat(), accpUnwrappedKey1.getFormat());
    assertEquals(sunUnwrappedKey.getAlgorithm(), accpUnwrappedKey2.getAlgorithm());
    assertEquals(sunUnwrappedKey.getFormat(), accpUnwrappedKey2.getFormat());
    assertArrayEquals(keyToBeWrapped.getEncoded(), sunUnwrappedKey.getEncoded());
    assertArrayEquals(keyToBeWrapped.getEncoded(), accpUnwrappedKey1.getEncoded());
    assertArrayEquals(keyToBeWrapped.getEncoded(), accpUnwrappedKey2.getEncoded());
  }

  private static Stream<Arguments> wrapUnwrapParams() {
    final List<Arguments> result = new ArrayList<>();
    for (int keySize : new int[] {128}) {
      for (long i = 16; i != 17; i++) {
        result.add(Arguments.of(i, keySize));
      }
    }
    return result.stream();
  }

  @Test
  public void whenBadPaddingWithUnwrap_expectException() throws Exception {
    final SecretKeySpec wrappingKey = genAesKey(0, 128);
    final IvParameterSpec iv = genIv(0, 16);
    final Cipher accp = accpCipher();
    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(
        InvalidKeyException.class,
        () -> accp.unwrap(genData(0, 16), "SECRET_KEY", Cipher.SECRET_KEY));
  }

  @Test
  public void whenWrappedKeyIsNotAligned_expectException() throws Exception {
    final SecretKeySpec wrappingKey = genAesKey(0, 128);
    final IvParameterSpec iv = genIv(0, 16);
    final Cipher accp = accpCipher();
    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(
        InvalidKeyException.class,
        () -> accp.unwrap(genData(0, 17), "SECRET_KEY", Cipher.SECRET_KEY));
  }

  @Test
  public void aesCbcBlockSizeIs16() {
    assertEquals(sunCipher().getBlockSize(), accpCipher().getBlockSize());
  }

  @Test
  public void whenDecryptingWithUnalignedInput_expectException() throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final byte[] input = new byte[23];

    final Cipher cipherDec = accpCipher();
    cipherDec.init(Cipher.DECRYPT_MODE, key, iv);
    assertThrows(IllegalBlockSizeException.class, () -> cipherDec.doFinal(input));

    // When performing multistep operations, unalignment is only detected during final
    assertDoesNotThrow(() -> cipherDec.update(input, 0, 20));
    assertThrows(IllegalBlockSizeException.class, () -> cipherDec.doFinal(input, 20, 3));
  }
}
