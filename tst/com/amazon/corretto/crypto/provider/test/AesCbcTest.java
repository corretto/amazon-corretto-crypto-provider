// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.byteBuffersAreEqual;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genAesKey;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genData;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genIv;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genPattern;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArray;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationExplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationImplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBuffer;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBufferInPlace;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBufferMultiAllocation;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepInPlaceArray;
import static com.amazon.corretto.crypto.provider.test.TestUtil.oneShotByteBuffer;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
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
public class AesCbcTest {
  private static final Provider bcProv = new BouncyCastleProvider();

  static Cipher accpAesCbcCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CBC/PKCS5Padding", TestUtil.NATIVE_PROVIDER)
          : Cipher.getInstance("AES/CBC/NoPadding", TestUtil.NATIVE_PROVIDER);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  static Cipher sunAesCbcCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE")
          : Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  static Cipher bcAesCbcCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CBC/PKCS7Padding", bcProv)
          : Cipher.getInstance("AES/CBC/NoPadding", bcProv);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void emptyCipherTextWithPaddingEnabledShouldProduceEmptyPlaintext() throws Exception {
    // For empty cipher text, SunJCE returns empty plain text when decrypting with padding enabled.
    // This is despite the fact that Cipher text with padding is always at least 16 bytes. This test
    // shows that ACCP is compatible with SunJCE in this manner. AWS-LC has a different behavior:
    // EVP_CipherFinal fails when no input is passed to decryption with PKCS7Padding.
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpAesCbcCipher(true);
    final Cipher sun = sunAesCbcCipher(true);

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
    final byte[] accpCipherText = accp.doFinal();
    assertEquals(16, accpCipherText.length);
    assertArrayEquals(sun.doFinal(), accpCipherText);
  }

  @Test
  public void ensureInputEmptyIsResetAfterAnOperation() throws Exception {
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpAesCbcCipher(true);

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
    final Cipher accp = accpAesCbcCipher(true);

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

  @Test
  public void testPkcs7Name() throws Exception {
    // SunJCE does not recognize AES/CBC/PKCS7Padding, but BouncyCastle does:
    assertThrows(
        NoSuchPaddingException.class, () -> Cipher.getInstance("AES/CBC/PKCS7Padding", "SunJCE"));

    final Cipher bcCipher = bcAesCbcCipher(true);
    final Cipher accpCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", TestUtil.NATIVE_PROVIDER);

    final byte[] data = genData(987, 23);
    final SecretKeySpec aesKey = genAesKey(987, 256);
    final IvParameterSpec iv = genIv(987, 16);

    bcCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] cipherText = bcCipher.doFinal(data);
    assertArrayEquals(cipherText, accpCipher.doFinal(data));

    bcCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertArrayEquals(data, bcCipher.doFinal(cipherText));
    assertArrayEquals(data, accpCipher.doFinal(cipherText));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testOneShotArray(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    final byte[] data = genData(seed, inputLen);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] cipherText = accpCipher.doFinal(data);
    assertArrayEquals(sunCipher.doFinal(data), cipherText);

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final byte[] plainText = accpCipher.doFinal(cipherText);
    assertArrayEquals(sunCipher.doFinal(cipherText), plainText);
    assertArrayEquals(data, plainText);
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testOneShotArrayInPlace(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int bufferLen = accpCipher.getOutputSize(inputLen);

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    final byte[] inputOutput = genData(seed, bufferLen);
    final byte[] input = Arrays.copyOf(inputOutput, inputLen);

    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(input);
    final int cipherTextLen = accpCipher.doFinal(inputOutput, 0, inputLen, inputOutput, 0);
    assertEquals(sunCipherText.length, cipherTextLen);
    assertTrue(
        byteBuffersAreEqual(
            ByteBuffer.wrap(sunCipherText), ByteBuffer.wrap(inputOutput, 0, cipherTextLen)));

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final int plainTextLen = accpCipher.doFinal(inputOutput, 0, cipherTextLen, inputOutput, 0);
    assertEquals(inputLen, plainTextLen);
    assertTrue(
        byteBuffersAreEqual(ByteBuffer.wrap(input), ByteBuffer.wrap(inputOutput, 0, plainTextLen)));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testMultiStepArray(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);

    final byte[] data = genData(seed, inputLen);
    final ByteBuffer dataByteBuff = ByteBuffer.wrap(data);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(data);
    final ByteBuffer sunCipherTextByteBuffer = ByteBuffer.wrap(sunCipherText);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer, multiStepArray(accpCipher, processingPattern, data)));
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer,
              multiStepArrayMultiAllocationImplicit(accpCipher, processingPattern, data)));
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer,
              multiStepArrayMultiAllocationExplicit(accpCipher, processingPattern, data)));
    }

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              ByteBuffer.wrap(data), multiStepArray(accpCipher, processingPattern, sunCipherText)));
      assertTrue(
          byteBuffersAreEqual(
              ByteBuffer.wrap(data),
              multiStepArrayMultiAllocationImplicit(accpCipher, processingPattern, sunCipherText)));
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff,
              multiStepArrayMultiAllocationExplicit(accpCipher, processingPattern, sunCipherText)));
    }
  }

  private static Stream<Arguments> arrayTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (final boolean isPaddingEnabled : new boolean[] {false, true}) {
        for (int i = 0; i != 32; i++) {
          if (!isPaddingEnabled && (i % 16 != 0)) continue;
          result.add(Arguments.of(keySize, (long) i, isPaddingEnabled, i));
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testMultiStepArrayInPlace(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    // With padding, the length of cipher text is greater than plaintext. The buffer needs to be set
    // to the size of the cipher text for in-place operations.
    final int bufferLen = accpCipher.getOutputSize(inputLen);
    final byte[] inputOutput = genData(seed, bufferLen);
    final byte[] input = Arrays.copyOf(inputOutput, inputLen);
    final ByteBuffer inputByteBuffer = ByteBuffer.wrap(input);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(input);
    final ByteBuffer sunCipherTextByteBuffer = ByteBuffer.wrap(sunCipherText);

    for (final List<Integer> processingPattern : processingPatterns) {
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final int cipherLen =
          multiStepInPlaceArray(accpCipher, processingPattern, inputOutput, inputLen);
      assertEquals(sunCipherText.length, cipherLen);
      assertTrue(
          byteBuffersAreEqual(sunCipherTextByteBuffer, ByteBuffer.wrap(inputOutput, 0, cipherLen)));
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      final int plainTextLen =
          multiStepInPlaceArray(accpCipher, processingPattern, inputOutput, cipherLen);
      assertEquals(inputLen, plainTextLen);
      assertTrue(
          byteBuffersAreEqual(inputByteBuffer, ByteBuffer.wrap(inputOutput, 0, plainTextLen)));
    }
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testOneShotByteBuffer(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    final ByteBuffer input = genData(seed, inputLen, inputDirect);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer accpCipherText =
        genData(seed, accpCipher.getOutputSize(input.remaining()), outputDirect);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText =
        genData(seed, sunCipher.getOutputSize(input.remaining()), false);
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

    final ByteBuffer sunInput = input.duplicate();
    final int sunCipherLen = sunCipher.doFinal(sunInput, sunCipherText);
    assertEquals(sunCipherLen, accpCipherLen);

    sunCipherText.flip();
    accpCipherText.flip();
    assertTrue(byteBuffersAreEqual(sunCipherText, accpCipherText));

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer accpPlainText =
        ByteBuffer.allocate(accpCipher.getOutputSize(accpCipherText.remaining()));
    assertEquals(inputLen, accpCipher.doFinal(accpCipherText, accpPlainText));
    accpPlainText.flip();
    assertTrue(byteBuffersAreEqual(input, accpPlainText));

    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer sunPlainText =
        ByteBuffer.allocate(sunCipher.getOutputSize(sunCipherText.remaining()));
    sunCipher.doFinal(sunCipherText, sunPlainText);
    sunPlainText.flip();
    assertTrue(byteBuffersAreEqual(sunPlainText, accpPlainText));
  }

  @ParameterizedTest
  @MethodSource("byteBufferInPlaceTestParams")
  public void testOneShotByteBufferInPlace(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean isDirect)
      throws Exception {

    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int bufferLen = accpCipher.getOutputSize(inputLen);
    final ByteBuffer buffer = genData(seed, bufferLen, isDirect);

    final ByteBuffer input = buffer.duplicate();
    input.limit(inputLen);

    final ByteBuffer cipherTextView = buffer.duplicate();

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);

    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, input.duplicate());

    assertEquals(sunCipherText.remaining(), accpCipher.doFinal(input, cipherTextView));
    cipherTextView.flip();
    assertTrue(byteBuffersAreEqual(sunCipherText, cipherTextView));

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer plainTextView = cipherTextView.duplicate();
    assertEquals(inputLen, accpCipher.doFinal(cipherTextView, plainTextView));
    plainTextView.flip();

    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer sunPlainText = sunCipherText.duplicate();
    sunCipher.doFinal(sunCipherText, sunPlainText);
    sunPlainText.flip();

    assertTrue(byteBuffersAreEqual(sunPlainText, plainTextView));
  }

  private static Stream<Arguments> byteBufferInPlaceTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (int i = 0; i != 1024; i++) {
        for (final boolean isPaddingEnabled : new boolean[] {true, false}) {
          for (final boolean isDirect : new boolean[] {true, false}) {
            if (!isPaddingEnabled && (i % 16 != 0)) continue;
            result.add(Arguments.of(keySize, (long) i, isPaddingEnabled, i, isDirect));
          }
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testMultiStepByteBuffer(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    final ByteBuffer input = genData(seed, inputLen, inputDirect);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText =
        genData(seed, sunCipher.getOutputSize(input.remaining()), false);
    final ByteBuffer sunInput = input.duplicate();
    sunCipher.doFinal(sunInput, sunCipherText);
    sunCipherText.flip();

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      final ByteBuffer accpInput =
          inputReadOnly ? input.duplicate().asReadOnlyBuffer() : input.duplicate();
      final ByteBuffer accpCipherText =
          multiStepByteBuffer(accpCipher, processingPattern, accpInput, outputDirect);
      // all the input must have been processed.
      assertEquals(0, accpInput.remaining());
      assertEquals(accpInput.limit(), accpInput.position());
      // limit for input should not change
      assertEquals(input.limit(), accpInput.limit());

      assertTrue(byteBuffersAreEqual(sunCipherText, accpCipherText));
    }
    for (final List<Integer> processingPattern : processingPatterns) {
      final ByteBuffer accpInput =
          inputReadOnly ? input.duplicate().asReadOnlyBuffer() : input.duplicate();
      final List<ByteBuffer> accpCipherTextChunks =
          multiStepByteBufferMultiAllocation(
              accpCipher, processingPattern, accpInput, outputDirect);
      // all the input must have been processed.
      assertEquals(0, accpInput.remaining());
      assertEquals(accpInput.limit(), accpInput.position());
      // limit for input should not change
      assertEquals(input.limit(), accpInput.limit());

      assertTrue(byteBuffersAreEqual(sunCipherText, accpCipherTextChunks));
    }

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      final ByteBuffer cipherText = sunCipherText.duplicate();
      final ByteBuffer accpPlainText =
          multiStepByteBuffer(accpCipher, processingPattern, cipherText, outputDirect);
      // all the input must have been processed.
      assertEquals(0, cipherText.remaining());
      assertEquals(cipherText.limit(), cipherText.position());

      assertTrue(byteBuffersAreEqual(input, accpPlainText));
    }
    for (final List<Integer> processingPattern : processingPatterns) {
      final ByteBuffer cipherText = sunCipherText.duplicate();
      final List<ByteBuffer> accpPlainTextChunks =
          multiStepByteBufferMultiAllocation(
              accpCipher, processingPattern, cipherText, outputDirect);
      // all the input must have been processed.
      assertEquals(0, cipherText.remaining());
      assertEquals(cipherText.limit(), cipherText.position());

      assertTrue(byteBuffersAreEqual(input, accpPlainTextChunks));
    }
  }

  private static Stream<Arguments> byteBufferTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (int i = 0; i != 512; i++) {
        for (final boolean isPaddingEnabled : new boolean[] {true, false}) {
          for (final boolean inputReadOnly : new boolean[] {true, false}) {
            for (final boolean inputDirect : new boolean[] {true, false}) {
              for (final boolean outputDirect : new boolean[] {true, false}) {
                if (!isPaddingEnabled && (i % 16 != 0)) continue;
                result.add(
                    Arguments.of(
                        keySize,
                        (long) i,
                        isPaddingEnabled,
                        i,
                        inputReadOnly,
                        inputDirect,
                        outputDirect));
              }
            }
          }
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("byteBufferInPlaceTestParams")
  public void testMultiStepByteBufferInPlace(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean isDirect)
      throws Exception {

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher accpCipher = accpAesCbcCipher(isPaddingEnabled);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int bufferLen = accpCipher.getOutputSize(inputLen);
    final ByteBuffer buffer = genData(seed, bufferLen, isDirect);

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    final ByteBuffer sunInput = buffer.duplicate();
    sunInput.limit(inputLen);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, sunInput);
    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer sunPlainText = oneShotByteBuffer(sunCipher, sunCipherText.duplicate());

    for (final List<Integer> processingPattern : processingPatterns) {
      final ByteBuffer input = buffer.duplicate();
      input.limit(inputLen);
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final ByteBuffer cipherText =
          multiStepByteBufferInPlace(accpCipher, processingPattern, input);
      assertTrue(byteBuffersAreEqual(sunCipherText, cipherText));

      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      final ByteBuffer plainText =
          multiStepByteBufferInPlace(accpCipher, processingPattern, cipherText);
      assertTrue(byteBuffersAreEqual(sunPlainText, plainText));
    }
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void usingSameKeyIvIsAllowed(final boolean isPaddingEnabled) throws Exception {
    final SecretKeySpec key = genAesKey(564, 256);
    final IvParameterSpec iv = genIv(644, 16);
    final byte[] input1 = genData(0, 256);
    final byte[] input2 = genData(1, 256);

    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);
    final Cipher sun = sunAesCbcCipher(isPaddingEnabled);

    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertArrayEquals(sun.doFinal(input1), accp.doFinal(input1));
    assertArrayEquals(sun.doFinal(input2), accp.doFinal(input2));

    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertArrayEquals(sun.doFinal(input1), accp.doFinal(input1));
    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    assertArrayEquals(sun.doFinal(input2), accp.doFinal(input2));
  }

  @ParameterizedTest
  @MethodSource("clobberingParams")
  public void outputClobberingInput_expectSuccess(
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final int clobberingIndex)
      throws Exception {
    final SecretKeySpec key = genAesKey(seed, 256);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);
    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    final Cipher sun = sunAesCbcCipher(isPaddingEnabled);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);

    final int cipherLen = accp.getOutputSize(inputLen);
    final byte[] buffer = genData(seed, clobberingIndex + cipherLen + clobberingIndex);

    final byte[] prefix = Arrays.copyOf(buffer, clobberingIndex);
    final byte[] postfix = Arrays.copyOfRange(buffer, clobberingIndex + cipherLen, buffer.length);

    final byte[] sunCipherText = sun.doFinal(buffer, 0, inputLen);

    assertEquals(sunCipherText.length, cipherLen);
    // output clobbers input
    assertEquals(sunCipherText.length, accp.doFinal(buffer, 0, inputLen, buffer, clobberingIndex));
    // prefix and postfix should be untouched
    assertTrue(Arrays.equals(prefix, Arrays.copyOf(buffer, clobberingIndex)));
    assertTrue(
        Arrays.equals(
            postfix, Arrays.copyOfRange(buffer, clobberingIndex + cipherLen, buffer.length)));
    // cipherText matches what we get from sun
    assertArrayEquals(
        sunCipherText, Arrays.copyOfRange(buffer, clobberingIndex, clobberingIndex + cipherLen));
  }

  private static Stream<Arguments> clobberingParams() {
    final List<Arguments> result = new ArrayList<>();
    for (int clobberingIndex = 1; clobberingIndex != 17; clobberingIndex++) {
      for (int i = 0; i != 1024; i++) {
        for (final boolean isPaddingEnabled : new boolean[] {true, false}) {
          if (!isPaddingEnabled && (i % 16 != 0)) continue;
          result.add(Arguments.of((long) i, isPaddingEnabled, i, clobberingIndex));
        }
      }
    }
    return result.stream();
  }

  @Test
  public void testOneShotPadding() throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec(
            TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            "AES");
    final byte[] input =
        TestUtil.decodeHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031");
    final IvParameterSpec iv =
        new IvParameterSpec(TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F"));
    final Cipher cbcPadding = accpAesCbcCipher(true);
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cbcPadding.doFinal(input);
    assertEquals(
        "F29000B62A499FD0A9F39A6ADD2E77809543B86FC046FA883A9446B82E47D12DA144FC255AAD45BF681D3A3773A325C275C285C2760F0ED66EB65CFBEED8781D",
        Hex.encodeHexString(cipherText, false));
    cbcPadding.init(Cipher.DECRYPT_MODE, key, iv);
    final ByteBuffer plainTextByteBuffer =
        multiStepArray(
            cbcPadding, Arrays.asList(0, 1, 1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5), cipherText);
    final byte[] plainText =
        Arrays.copyOf(plainTextByteBuffer.array(), plainTextByteBuffer.limit());
    assertArrayEquals(input, plainText);
  }

  @Test
  public void testOneShotPaddingDirect() throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec(
            TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            "AES");
    final byte[] input =
        TestUtil.decodeHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031");
    final ByteBuffer directInput = ByteBuffer.allocateDirect(input.length);
    directInput.put(input).flip();
    final IvParameterSpec iv =
        new IvParameterSpec(TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F"));
    final Cipher cbcPadding = accpAesCbcCipher(true);
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final ByteBuffer cipherText = ByteBuffer.allocate(input.length + 16);
    final int cipherLen = cbcPadding.doFinal(directInput, cipherText);
    cipherText.flip();
    assertEquals(cipherLen, cipherText.remaining());
    assertEquals(
        "F29000B62A499FD0A9F39A6ADD2E77809543B86FC046FA883A9446B82E47D12DA144FC255AAD45BF681D3A3773A325C275C285C2760F0ED66EB65CFBEED8781D",
        Hex.encodeHexString(Arrays.copyOf(cipherText.array(), cipherText.remaining()), false));
  }

  @Test
  public void testOneShotPaddingReadOnly() throws Exception {
    final SecretKeySpec key =
        new SecretKeySpec(
            TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            "AES");
    final byte[] input =
        TestUtil.decodeHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031");
    final ByteBuffer inputBuffer = ByteBuffer.allocate(input.length);
    inputBuffer.put(input).flip();
    final IvParameterSpec iv =
        new IvParameterSpec(TestUtil.decodeHex("000102030405060708090A0B0C0D0E0F"));
    final Cipher cbcPadding = accpAesCbcCipher(true);
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final ByteBuffer cipherText =
        multiStepByteBuffer(cbcPadding, Arrays.asList(0, 5, 5, 5, 5, 20), inputBuffer, false);
    assertEquals(
        "F29000B62A499FD0A9F39A6ADD2E77809543B86FC046FA883A9446B82E47D12DA144FC255AAD45BF681D3A3773A325C275C285C2760F0ED66EB65CFBEED8781D",
        Hex.encodeHexString(Arrays.copyOf(cipherText.array(), cipherText.remaining()), false));
  }

  @ParameterizedTest
  @MethodSource("wrapUnwrapParams")
  public void wrapUnwrapIsCompatibleWithSun(
      final long seed, final boolean isPaddingEnabled, final int keySize, final int inputLen)
      throws Exception {
    final String alg = "SECRET_KEY";
    final SecretKeySpec wrappingKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);
    accp.init(Cipher.WRAP_MODE, wrappingKey, iv);
    final Cipher sun = sunAesCbcCipher(isPaddingEnabled);
    sun.init(Cipher.WRAP_MODE, wrappingKey, iv);

    final SecretKeySpec keyToBeWrapped = new SecretKeySpec(genData(seed, inputLen), alg);

    final byte[] sunWrappedKey = sun.wrap(keyToBeWrapped);
    final byte[] accpWrappedKey = accp.wrap(keyToBeWrapped);

    assertArrayEquals(sunWrappedKey, accpWrappedKey);

    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    sun.init(Cipher.UNWRAP_MODE, wrappingKey, iv);

    final Key sunUnwrappedKey = sun.unwrap(sunWrappedKey, alg, Cipher.SECRET_KEY);
    final Key accpUnwrappedKey = accp.unwrap(sunWrappedKey, alg, Cipher.SECRET_KEY);

    assertEquals(sunUnwrappedKey.getAlgorithm(), accpUnwrappedKey.getAlgorithm());
    assertEquals(sunUnwrappedKey.getFormat(), accpUnwrappedKey.getFormat());
    assertArrayEquals(keyToBeWrapped.getEncoded(), sunUnwrappedKey.getEncoded());
    assertArrayEquals(keyToBeWrapped.getEncoded(), accpUnwrappedKey.getEncoded());
  }

  private static Stream<Arguments> wrapUnwrapParams() {
    final List<Arguments> result = new ArrayList<>();
    for (int keySize : new int[] {128}) {
      for (final boolean isPaddingEnabled : new boolean[] {true, false}) {
        for (int i = 16; i != 128; i++) {
          if (!isPaddingEnabled && (i % 16 != 0)) continue;
          result.add(Arguments.of((long) i, isPaddingEnabled, keySize, i));
        }
      }
    }
    return result.stream();
  }

  @Test
  public void whenBadPaddingWithUnwrap_expectException() throws Exception {
    final SecretKeySpec wrappingKey = genAesKey(0, 128);
    final IvParameterSpec iv = genIv(0, 16);
    final Cipher accp = accpAesCbcCipher(true);
    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(
        InvalidKeyException.class,
        () -> accp.unwrap(genData(0, 16), "SECRET_KEY", Cipher.SECRET_KEY));

    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(
        InvalidKeyException.class,
        () -> accp.unwrap(genData(0, 17), "SECRET_KEY", Cipher.SECRET_KEY));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenWrappedKeyIsNotAligned_expectException(final boolean isPaddingEnabled)
      throws Exception {
    final SecretKeySpec wrappingKey = genAesKey(0, 128);
    final IvParameterSpec iv = genIv(0, 16);
    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);
    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(
        InvalidKeyException.class,
        () -> accp.unwrap(genData(0, 17), "SECRET_KEY", Cipher.SECRET_KEY));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void wrapUnwrapCanOnlyBeAfterInitialization(final boolean isPaddingEnabled) {
    final String alg = "SECRET_KEY";
    final SecretKeySpec keyToBeWrapped = new SecretKeySpec(genData(0, 16), alg);

    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);

    // Cipher must be initialized before wrap/unwrap
    assertThrows(IllegalStateException.class, () -> accp.wrap(keyToBeWrapped));
    assertThrows(
        IllegalStateException.class,
        () -> accp.unwrap(keyToBeWrapped.getEncoded(), alg, Cipher.SECRET_KEY));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void wrapUnwrapCanOnlyBeUsedIfCipherIsInitializedForWrapUnwrap(
      final boolean isPaddingEnabled) throws Exception {
    final SecretKeySpec wrappingKey = genAesKey(0, 128);
    final IvParameterSpec iv = genIv(0, 16);
    final String alg = "SECRET_KEY";
    final SecretKeySpec keyToBeWrapped = new SecretKeySpec(genData(0, 16), alg);

    final Cipher accp = accpAesCbcCipher(isPaddingEnabled);

    accp.init(Cipher.ENCRYPT_MODE, wrappingKey, iv);
    assertThrows(IllegalStateException.class, () -> accp.wrap(keyToBeWrapped));

    accp.init(Cipher.DECRYPT_MODE, wrappingKey, iv);
    assertThrows(
        IllegalStateException.class,
        () -> accp.unwrap(keyToBeWrapped.getEncoded(), alg, Cipher.SECRET_KEY));

    accp.init(Cipher.WRAP_MODE, wrappingKey, iv);
    assertThrows(IllegalStateException.class, () -> accp.update(wrappingKey.getEncoded()));

    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(IllegalStateException.class, () -> accp.update(wrappingKey.getEncoded()));

    accp.init(Cipher.WRAP_MODE, wrappingKey, iv);
    assertThrows(IllegalStateException.class, () -> accp.doFinal(wrappingKey.getEncoded()));

    accp.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    assertThrows(IllegalStateException.class, () -> accp.doFinal(wrappingKey.getEncoded()));
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
    final Cipher cbcPadding = accpAesCbcCipher(true);
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cbcPadding.doFinal(input);
    assertEquals(
        "F29000B62A499FD0A9F39A6ADD2E77809543B86FC046FA883A9446B82E47D12DA144FC255AAD45BF681D3A3773A325C275C285C2760F0ED66EB65CFBEED8781D",
        Hex.encodeHexString(cipherText, false));
    cipherText[cipherText.length - 1] = (byte) (0xFF ^ cipherText[cipherText.length - 1]);
    cbcPadding.init(Cipher.DECRYPT_MODE, key, iv);
    assertThrows(BadPaddingException.class, () -> cbcPadding.doFinal(cipherText));
    // The cipher will need to be initialized again.
    assertThrows(IllegalStateException.class, () -> cbcPadding.doFinal(cipherText));

    final Cipher cipherFresh = accpAesCbcCipher(true);
    cipherFresh.init(Cipher.DECRYPT_MODE, key, iv);
    assertThrows(BadPaddingException.class, () -> cipherFresh.doFinal(cipherText));
    // The cipher will need to be initialized again.
    assertThrows(IllegalStateException.class, () -> cipherFresh.doFinal(cipherText));
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
    final Cipher cbcPadding = accpAesCbcCipher(true);
    cbcPadding.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cbcPadding.doFinal(input);
    assertEquals(
        "F29000B62A499FD0A9F39A6ADD2E77809543B86FC046FA883A9446B82E47D12DA144FC255AAD45BF681D3A3773A325C275C285C2760F0ED66EB65CFBEED8781D",
        Hex.encodeHexString(cipherText, false));
    cipherText[cipherText.length - 1] = (byte) (0xFF ^ cipherText[cipherText.length - 1]);
    cbcPadding.init(Cipher.DECRYPT_MODE, key, iv);
    assertDoesNotThrow(() -> cbcPadding.update(cipherText, 0, 16));
    assertThrows(
        BadPaddingException.class,
        () -> cbcPadding.doFinal(cipherText, 16, cipherText.length - 16));
    // The cipher will need to be initialized again.
    assertThrows(IllegalStateException.class, () -> cbcPadding.doFinal(cipherText));
  }

  private static Stream<Arguments> paddings() {
    return Stream.of(Arguments.of(true), Arguments.of(false));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void aesCbcBlockSizeIs16(final boolean isPaddingEnabled) {
    assertEquals(16, accpAesCbcCipher(isPaddingEnabled).getBlockSize());
    assertEquals(16, sunAesCbcCipher(isPaddingEnabled).getBlockSize());
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenGetOutputSizeWithUninitializedCipher_expectException(
      final boolean isPaddingEnabled) {
    // The exceptions are not thrown by ACCP.
    assertThrows(
        IllegalStateException.class, () -> accpAesCbcCipher(isPaddingEnabled).getOutputSize(10));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenGetIVOnUninitializedCipher_expectNull(final boolean isPaddingEnabled) {
    assertNull(accpAesCbcCipher(isPaddingEnabled).getIV());
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenGetParametersOnInitializedCipher_expectSameIv(final boolean isPaddingEnabled)
      throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final IvParameterSpec ivFromParams =
        cipher.getParameters().getParameterSpec(IvParameterSpec.class);
    assertArrayEquals(cipher.getIV(), ivFromParams.getIV());
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenGetParametersOnUninitializedCipher_expectDifferentIvs(
      final boolean isPaddingEnabled) throws Exception {
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    final IvParameterSpec iv1 = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
    final IvParameterSpec iv2 = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
    assertFalse(Arrays.equals(iv1.getIV(), iv2.getIV()));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitializingWithNoIvDuringDecrypt_expectException(
      final boolean isPaddingEnabled) {
    final SecretKeySpec key = genAesKey(1, 128);
    final SecureRandom random = new SecureRandom();
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    assertThrows(InvalidKeyException.class, () -> cipher.init(Cipher.DECRYPT_MODE, key, random));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitializingWithNoIvForEncryptionOrWrap_expectSuccess(
      final boolean isPaddingEnabled) {
    final SecretKeySpec key = genAesKey(1, 128);
    final SecureRandom random = new SecureRandom();
    for (final int mode : new int[] {Cipher.ENCRYPT_MODE, Cipher.WRAP_MODE}) {
      final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
      assertDoesNotThrow(() -> cipher.init(mode, key, random));
    }
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitializedWithParam_expectSameIv(final boolean isPaddingEnabled)
      throws Exception {
    final SecretKeySpec key = genAesKey(1, 128);
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    final AlgorithmParameters params = cipher.getParameters();
    cipher.init(Cipher.ENCRYPT_MODE, key, params, null);
    assertArrayEquals(cipher.getIV(), params.getParameterSpec(IvParameterSpec.class).getIV());
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitializingWithInvalidMode_expectException(final boolean isPaddingEnabled) {
    final SecretKeySpec key = genAesKey(1, 128);
    final IvParameterSpec iv = genIv(1, 16);
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    assertThrows(InvalidParameterException.class, () -> cipher.init(0, key, iv));
    assertThrows(InvalidParameterException.class, () -> cipher.init(5, key, iv));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitializingWithBadIv_expectException(final boolean isPaddingEnabled) {
    final SecretKeySpec key = genAesKey(1, 128);

    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    // Only IvParameterSpec is supported.
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new AlgorithmParameterSpec() {}));

    // Iv cannot be null. We don't need to check for IvParameterSpec.getIV() == null
    assertThrows(NullPointerException.class, () -> new IvParameterSpec(null));

    // Iv's length must be 16
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, genIv(1, 10)));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenUpdateOrFinalWithShortBuffer_expectException(final boolean isPaddingEnabled)
      throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final ByteBuffer input = ByteBuffer.allocate(16);
    final ByteBuffer output = ByteBuffer.allocate(5);
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    assertThrows(ShortBufferException.class, () -> cipher.doFinal(input, output));
    assertThrows(ShortBufferException.class, () -> cipher.update(input, output));
  }

  @ParameterizedTest
  @MethodSource("aesCbcKatFromOpenSSL")
  public void aesCbcKnownAnswerTests(
      final String keyStr, final String ivStr, final String plainText, final String cipherText)
      throws Exception {
    final SecretKeySpec key = new SecretKeySpec(TestUtil.decodeHex(keyStr), "AES");
    final IvParameterSpec iv = new IvParameterSpec(TestUtil.decodeHex(ivStr));
    final Cipher cipher = accpAesCbcCipher(false);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    assertEquals(
        cipherText.toUpperCase(),
        Hex.encodeHexString(cipher.doFinal(TestUtil.decodeHex(plainText)), false));

    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    assertEquals(
        plainText.toUpperCase(),
        Hex.encodeHexString(cipher.doFinal(TestUtil.decodeHex(cipherText)), false));
  }

  private static Stream<Arguments> aesCbcKatFromOpenSSL() {
    // These tests come from the following URL:
    // https://github.com/majek/openssl/blob/master/crypto/evp/evptests.txt
    // cipher:key:iv:plaintext:ciphertext
    return Stream.of(
            "AES-128-CBC:00000000000000000000000000000000:00000000000000000000000000000000:f34481ec3cc627bacd5dc3fb08f273e6:0336763e966d92595a567cc9ce537f5e",
            "AES-128-CBC:2B7E151628AED2A6ABF7158809CF4F3C:000102030405060708090A0B0C0D0E0F:6BC1BEE22E409F96E93D7E117393172A:7649ABAC8119B246CEE98E9B12E9197D",
            "AES-128-CBC:2B7E151628AED2A6ABF7158809CF4F3C:7649ABAC8119B246CEE98E9B12E9197D:AE2D8A571E03AC9C9EB76FAC45AF8E51:5086CB9B507219EE95DB113A917678B2",
            "AES-128-CBC:2B7E151628AED2A6ABF7158809CF4F3C:5086CB9B507219EE95DB113A917678B2:30C81C46A35CE411E5FBC1191A0A52EF:73BED6B8E3C1743B7116E69E22229516",
            "AES-128-CBC:2B7E151628AED2A6ABF7158809CF4F3C:73BED6B8E3C1743B7116E69E22229516:F69F2445DF4F9B17AD2B417BE66C3710:3FF1CAA1681FAC09120ECA307586E1A7",
            "AES-192-CBC:8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B:000102030405060708090A0B0C0D0E0F:6BC1BEE22E409F96E93D7E117393172A:4F021DB243BC633D7178183A9FA071E8",
            "AES-192-CBC:8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B:4F021DB243BC633D7178183A9FA071E8:AE2D8A571E03AC9C9EB76FAC45AF8E51:B4D9ADA9AD7DEDF4E5E738763F69145A",
            "AES-192-CBC:8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B:B4D9ADA9AD7DEDF4E5E738763F69145A:30C81C46A35CE411E5FBC1191A0A52EF:571B242012FB7AE07FA9BAAC3DF102E0",
            "AES-192-CBC:8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B:571B242012FB7AE07FA9BAAC3DF102E0:F69F2445DF4F9B17AD2B417BE66C3710:08B0E27988598881D920A9E64F5615CD",
            "AES-256-CBC:603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4:000102030405060708090A0B0C0D0E0F:6BC1BEE22E409F96E93D7E117393172A:F58C4C04D6E5F1BA779EABFB5F7BFBD6",
            "AES-256-CBC:603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4:F58C4C04D6E5F1BA779EABFB5F7BFBD6:AE2D8A571E03AC9C9EB76FAC45AF8E51:9CFC4E967EDB808D679F777BC6702C7D",
            "AES-256-CBC:603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4:9CFC4E967EDB808D679F777BC6702C7D:30C81C46A35CE411E5FBC1191A0A52EF:39F23369A9D9BACFA530E26304231461",
            "AES-256-CBC:603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4:39F23369A9D9BACFA530E26304231461:F69F2445DF4F9B17AD2B417BE66C3710:B2EB05E2C39BE9FCDA6C19078C6A9D1B")
        .map(
            testCase -> {
              final String[] rawTestCase = testCase.split(":");
              return Arguments.of(rawTestCase[1], rawTestCase[2], rawTestCase[3], rawTestCase[4]);
            });
  }

  @Test
  public void whenNoPaddingOrDecryptingWithUnalignedInput_expectException() throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final byte[] input = new byte[23];

    final Cipher cipherEnc = accpAesCbcCipher(false);
    cipherEnc.init(Cipher.ENCRYPT_MODE, key, iv);
    assertThrows(IllegalBlockSizeException.class, () -> cipherEnc.doFinal(input));

    final Cipher cipherDec = accpAesCbcCipher(true);
    cipherDec.init(Cipher.DECRYPT_MODE, key, iv);
    assertThrows(IllegalBlockSizeException.class, () -> cipherDec.doFinal(input));

    // When performing multistep operations, unalignment is only detected during final
    assertDoesNotThrow(() -> cipherEnc.update(input, 0, 20));
    assertThrows(IllegalBlockSizeException.class, () -> cipherEnc.doFinal(input, 20, 3));

    assertDoesNotThrow(() -> cipherDec.update(input, 0, 20));
    assertThrows(IllegalBlockSizeException.class, () -> cipherDec.doFinal(input, 20, 3));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void whenInitUpdateInitDoFinal_expectSuccess(final boolean isPaddingEnabled)
      throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final byte[] input = new byte[16];

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = sunCipher.doFinal(input);

    // This pattern of invocation is strange; however, nothing in the spec forbids it.
    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    cipher.update(input);
    // Let's forget what we were doing and do init followed by final.
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    assertArrayEquals(cipherText, cipher.doFinal(input));

    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    // Using cipher.update will produce same result, but this should be doFinal. Please have a look
    // at the following test for the reason.
    assertArrayEquals(input, cipher.doFinal(cipherText));
  }

  @ParameterizedTest
  @MethodSource("paddings")
  public void
      whenInputIsAMultipleOfBlockSizeUpdateAndDoFinalProduceSameResultDuringDecrypt_expectSuccess(
          final boolean isPaddingEnabled) throws Exception {
    final IvParameterSpec iv = genIv(1, 16);
    final SecretKeySpec key = genAesKey(1, 128);
    final byte[] input = new byte[16];

    final Cipher sunCipher = sunAesCbcCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = sunCipher.doFinal(input);

    final Cipher cipher = accpAesCbcCipher(isPaddingEnabled);

    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    assertArrayEquals(input, cipher.doFinal(cipherText));
    // Update will produce the same result as doFinal even padding is enabled. The reason is that
    // when input is aligned, decrypt-final does not produce any output.
    assertArrayEquals(input, cipher.update(cipherText));
  }
}
