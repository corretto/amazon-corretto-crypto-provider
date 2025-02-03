// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.getJavaVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.versionCompare;
import static org.junit.Assume.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AESGenerativeTest {
  private static final int[] KEY_SIZES = new int[] {128, 192, 256};
  private static final double P_LARGE = 0.1;
  private static final int LARGE_BUF_BASE_SIZE = 512 * 1024;
  private static final int BUF_SIZE_SPREAD = 1024;

  String algorithm = "AES/GCM/NoPadding";
  Cipher jceCipherEncrypt, jceCipherDecrypt;
  Cipher amzCipherEncrypt, amzCipherDecrypt;

  @AfterEach
  public void teardown() {
    jceCipherEncrypt = null;
    jceCipherDecrypt = null;
    amzCipherEncrypt = null;
    amzCipherDecrypt = null;
  }

  @Test
  public void testEncrypt91() throws Exception {
    // The implementation of javax.crypto.CipherSpi::bufferCrypt in JDK 10
    // has an issue that has been resolved in the following PR:
    // https://github.com/openjdk/jdk/commit/c3a97b27e244f97c80a14388aea4fc425006a87e
    // We disable this test for JDK 10.

    // To replicate the error for other JDKs, copy-paste the buggy implementation into
    // AesGcmSpi.java
    // and run `./gradlew cmake_clean single_test
    // -DSINGLE_TEST=com.amazon.corretto.crypto.provider.test.AESGenerativeTest`
    // The buggy implementation is available here:
    // https://github.com/openjdk/jdk/blob/f98aad58dea1d0b818706215166bcbbc349d1c6d/src/java.base/share/classes/javax/crypto/CipherSpi.java#L736-L857
    assumeTrue(getJavaVersion() != 10);
    try {
      testEncrypt(91, 10);
    } catch (Throwable t) {
      throw new AssertionError("Seed: 91", t);
    }
  }

  @Test
  public void testEncryptRandomly() throws Exception {
    for (int i = 0; i < 100; i++) {
      // when i == 91, the test case fails for JDK 10. This case is tested in another method:
      // testEncrypt91
      if (i == 91) {
        continue;
      }
      try {
        testEncrypt(i, 10);
      } catch (Throwable t) {
        throw new AssertionError("Seed: " + i, t);
      }
    }
  }

  @Test
  public void testWrapRandomly() throws Throwable {
    for (int i = 0; i < 100; i++) {
      testWrap(i, 16);
      testWrap(i, 24);
      testWrap(i, 32);
      testWrap(i, 1024);
      testWrap(i, 2048);
    }
  }

  private void testWrap(long seed, int keySize) throws Throwable {
    Random r = new Random(seed + keySize);
    maybeReInitWrap(r);

    final byte[] data;
    final String alg;
    final int keyType;
    final Key innerKey;
    final Class<? extends Key> clazz;
    if (keySize < 512) {
      // Symmetric key
      data = new byte[keySize * 8];
      r.nextBytes(data);
      alg = "AES";
      keyType = Cipher.SECRET_KEY;
      clazz = SecretKey.class;
      innerKey = new SecretKeySpec(data, alg);
    } else {
      // Asymmetric key
      alg = "RSA";
      // For speed, we'll try to get a native copy, but we don't require it
      KeyPairGenerator kg;
      try {
        kg = KeyPairGenerator.getInstance("RSA", NATIVE_PROVIDER);
        kg.initialize(keySize);
      } catch (final Exception ex) {
        kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(keySize);
      }
      KeyPair keyPair = kg.generateKeyPair();
      if (r.nextBoolean()) {
        innerKey = keyPair.getPublic();
        keyType = Cipher.PUBLIC_KEY;
        clazz = PublicKey.class;
      } else {
        innerKey = keyPair.getPrivate();
        keyType = Cipher.PRIVATE_KEY;
        clazz = PrivateKey.class;
      }
      data = innerKey.getEncoded();
    }

    byte[] wrappedJce = jceCipherEncrypt.wrap(innerKey);
    byte[] wrappedAmz = amzCipherEncrypt.wrap(innerKey);
    assertArrayEquals(wrappedJce, wrappedAmz);
    Key unwrappedJce = jceCipherDecrypt.unwrap(wrappedAmz, alg, keyType);
    Key unwrappedAmz = amzCipherDecrypt.unwrap(wrappedJce, alg, keyType);
    assertEquals(alg, unwrappedJce.getAlgorithm());
    assertEquals(alg, unwrappedAmz.getAlgorithm());
    assertArrayEquals(data, unwrappedJce.getEncoded());
    assertArrayEquals(data, unwrappedAmz.getEncoded());
    assertTrue(clazz.isAssignableFrom(unwrappedJce.getClass()));
    assertTrue(clazz.isAssignableFrom(unwrappedAmz.getClass()));
  }

  private void maybeReInitWrap(Random r)
      throws NoSuchAlgorithmException,
          NoSuchProviderException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException {
    maybeReinit(r, Cipher.WRAP_MODE, Cipher.UNWRAP_MODE);
  }

  private void maybeReinit(Random r)
      throws NoSuchAlgorithmException,
          NoSuchProviderException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException {
    maybeReinit(r, Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE);
  }

  @SuppressWarnings("fallthrough")
  private void maybeReinit(Random r, int encryptMode, int decryptMode)
      throws NoSuchAlgorithmException,
          NoSuchProviderException,
          NoSuchPaddingException,
          InvalidKeyException,
          InvalidAlgorithmParameterException {
    int resetType = r.nextInt(2);
    if (jceCipherEncrypt == null) resetType = 0;

    switch (resetType) {
      case 0:
        {
          // Allocate new cipher objects
          jceCipherEncrypt = Cipher.getInstance(algorithm, "SunJCE");
          jceCipherDecrypt = Cipher.getInstance(algorithm, "SunJCE");
          amzCipherEncrypt = Cipher.getInstance(algorithm, NATIVE_PROVIDER);
          amzCipherDecrypt = Cipher.getInstance(algorithm, NATIVE_PROVIDER);
        } // fall through to init
      case 1:
        {
          // Re-init existing ciphers
          byte[] iv =
              new byte[r.nextInt(53) + 12]; // use IVs of random length between 12 and 64 bytes
          byte[] keybytes = new byte[KEY_SIZES[r.nextInt(KEY_SIZES.length)] / 8];
          r.nextBytes(iv);
          r.nextBytes(keybytes);
          int tlen = 96 + 8 * ThreadLocalRandom.current().nextInt(5);

          SecretKeySpec key = new SecretKeySpec(keybytes, "AES");
          // SunJCE doesn't support IvParameterSpec, so we always use GCMParameterSpec
          jceCipherEncrypt.init(encryptMode, key, new GCMParameterSpec(tlen, iv));
          jceCipherDecrypt.init(decryptMode, key, new GCMParameterSpec(tlen, iv));
          if (tlen == 128
              && ThreadLocalRandom.current().nextBoolean()
              &&
              // We only added support for IvParameterSpec in version 1.0
              versionCompare("1.0", amzCipherEncrypt.getProvider()) <= 0) {
            amzCipherEncrypt.init(encryptMode, key, new IvParameterSpec(iv));
            amzCipherDecrypt.init(decryptMode, key, new IvParameterSpec(iv));
          } else {
            amzCipherEncrypt.init(encryptMode, key, new GCMParameterSpec(tlen, iv));
            amzCipherDecrypt.init(decryptMode, key, new GCMParameterSpec(tlen, iv));
          }
          assertArrayEquals(jceCipherEncrypt.getIV(), amzCipherEncrypt.getIV());

          break;
        }
    }
  }

  private void testEncrypt(long seed, int chunkCount) throws Throwable {
    Random r = new Random(seed);

    maybeReinit(r);

    ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    ByteArrayOutputStream jceResult = new ByteArrayOutputStream();
    ByteArrayOutputStream amzResult = new ByteArrayOutputStream();

    int aadChunks = r.nextInt(chunkCount);
    for (int i = 0; i < aadChunks; i++) {
      updateAAD(r, aadData);
    }

    for (int i = 0; i < chunkCount; i++) {
      updateRandomChunk(r, jceResult, amzResult);
    }

    randomDoFinal(r, jceResult, amzResult);

    assertArrayEquals(jceResult.toByteArray(), amzResult.toByteArray());

    // Now test decrypt
    byte[] decrypted = testDecrypt(r, aadData.toByteArray(), jceResult.toByteArray());
    jceCipherDecrypt.updateAAD(aadData.toByteArray());
    byte[] expectedPlaintext = jceCipherDecrypt.doFinal(jceResult.toByteArray());

    assertArrayEquals(expectedPlaintext, decrypted);
  }

  private void updateAAD(Random r, ByteArrayOutputStream aadData) throws Throwable {
    int bufferType = r.nextInt(2);
    int bufferLength =
        r.nextDouble() < P_LARGE
            ? LARGE_BUF_BASE_SIZE + r.nextInt(BUF_SIZE_SPREAD)
            : r.nextInt(BUF_SIZE_SPREAD);

    ByteBuffer buf =
        getBuffer(r, bufferType == 0, bufferType == 0 && r.nextBoolean(), bufferLength);

    switch (bufferType) {
      case 0:
        {
          jceCipherEncrypt.updateAAD(buf.duplicate());
          final ByteBuffer amzBuf = buf.duplicate();
          amzCipherEncrypt.updateAAD(amzBuf);
          assertByteBufferEmpty(amzBuf);

          Channels.newChannel(aadData).write(buf);

          break;
        }
      case 1:
        {
          byte[] adata = buf.array();

          jceCipherEncrypt.updateAAD(adata, buf.position(), buf.remaining());
          amzCipherEncrypt.updateAAD(adata, buf.position(), buf.remaining());

          Channels.newChannel(aadData).write(buf);

          break;
        }
    }
  }

  private void randomDoFinal(
      Random r, ByteArrayOutputStream jceResult, ByteArrayOutputStream amzResult)
      throws IOException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    switch (r.nextInt(3)) {
      case 0:
        {
          // Just doFinal()
          jceResult.write(jceCipherEncrypt.doFinal());
          amzResult.write(amzCipherEncrypt.doFinal());
          break;
        }
      case 1:
        {
          // Pass in a byte array
          int bufferLength =
              r.nextDouble() < P_LARGE
                  ? LARGE_BUF_BASE_SIZE + r.nextInt(BUF_SIZE_SPREAD)
                  : r.nextInt(BUF_SIZE_SPREAD);

          ByteBuffer buf = getBuffer(r, false, false, bufferLength);

          jceResult.write(
              jceCipherEncrypt.doFinal(buf.array(), buf.arrayOffset(), buf.remaining()));
          amzResult.write(
              amzCipherEncrypt.doFinal(buf.array(), buf.arrayOffset(), buf.remaining()));
          break;
        }
      case 2:
        {
          // Pass in a ByteBuffer
          int bufferLength =
              r.nextDouble() < P_LARGE
                  ? LARGE_BUF_BASE_SIZE + r.nextInt(BUF_SIZE_SPREAD)
                  : r.nextInt(BUF_SIZE_SPREAD);
          boolean nativeOutput = r.nextBoolean();

          ByteBuffer finalData = getBuffer(r, r.nextBoolean(), r.nextBoolean(), bufferLength);
          byteBufferDoFinal(nativeOutput, jceCipherEncrypt, jceResult, finalData);
          byteBufferDoFinal(nativeOutput, amzCipherEncrypt, amzResult, finalData);
        }
    }
  }

  private void updateRandomChunk(
      Random r, ByteArrayOutputStream jceResult, ByteArrayOutputStream amzResult)
      throws ShortBufferException, IOException {
    int bufferType = r.nextInt(3);
    int bufferLength =
        r.nextDouble() < P_LARGE
            ? LARGE_BUF_BASE_SIZE + r.nextInt(BUF_SIZE_SPREAD)
            : r.nextInt(BUF_SIZE_SPREAD);

    ByteBuffer buf =
        getBuffer(r, bufferType == 0, bufferType == 0 && r.nextBoolean(), bufferLength);

    switch (bufferType) {
      case 0:
        {
          ByteBuffer outBuf = ByteBuffer.allocate(jceCipherEncrypt.getOutputSize(buf.remaining()));
          jceCipherEncrypt.update(buf.duplicate(), outBuf);
          outBuf.flip();
          Channels.newChannel(jceResult).write(outBuf);

          outBuf = ByteBuffer.allocate(amzCipherEncrypt.getOutputSize(buf.remaining()));
          final ByteBuffer amzBuf = buf.duplicate();
          amzCipherEncrypt.update(amzBuf, outBuf);
          assertByteBufferEmpty(amzBuf);
          outBuf.flip();
          Channels.newChannel(amzResult).write(outBuf);

          break;
        }
      case 1:
        {
          byte[] adata = buf.array();

          jceResult.write(
              nullToEmpty(jceCipherEncrypt.update(adata, buf.position(), buf.remaining())));
          amzResult.write(
              nullToEmpty(amzCipherEncrypt.update(adata, buf.position(), buf.remaining())));
          break;
        }
      case 2:
        {
          byte[] adata = buf.array();

          int offset = r.nextInt(4);
          byte[] outBuf = new byte[jceCipherEncrypt.getOutputSize(buf.remaining()) + offset];
          int bytesWritten =
              jceCipherEncrypt.update(adata, buf.position(), buf.remaining(), outBuf, offset);
          jceResult.write(outBuf, offset, bytesWritten);

          outBuf = new byte[amzCipherEncrypt.getOutputSize(buf.remaining()) + offset];
          bytesWritten =
              amzCipherEncrypt.update(adata, buf.position(), buf.remaining(), outBuf, offset);
          amzResult.write(outBuf, offset, bytesWritten);
          break;
        }
    }
  }

  private byte[] testDecrypt(Random r, byte[] aadData, byte[] ciphertext) throws Exception {
    int nAADSteps = r.nextInt(10) + 1;
    int nDataSteps = r.nextInt(10) + 1;

    int[] aadSplits = builtSplitArray(r, nAADSteps, aadData.length);
    int[] dataSplits = builtSplitArray(r, nDataSteps, ciphertext.length);

    if (r.nextBoolean()) {
      // Half of the time, exercise a doFinal() with no new input data
      dataSplits[dataSplits.length - 1] = ciphertext.length;
    }

    int prevPtr = 0;
    for (int i = 0; i < aadSplits.length; i++) {
      applyAAD(r, amzCipherDecrypt, aadData, prevPtr, aadSplits[i]);
      prevPtr = aadSplits[i];
    }
    applyAAD(r, amzCipherDecrypt, aadData, aadSplits[aadSplits.length - 1], aadData.length);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    prevPtr = 0;
    for (int i = 0; i < dataSplits.length; i++) {
      applyDecryptUpdate(baos, r, amzCipherDecrypt, ciphertext, prevPtr, dataSplits[i]);
      prevPtr = dataSplits[i];
    }

    applyDoFinal(baos, r, amzCipherDecrypt, ciphertext, prevPtr);

    return baos.toByteArray();
  }

  private void applyDoFinal(
      ByteArrayOutputStream baos, Random r, Cipher cipher, byte[] ciphertext, int start)
      throws Exception {
    if (r.nextBoolean()) {
      applyDecryptUpdate(baos, r, cipher, ciphertext, start, ciphertext.length);
      baos.write(cipher.doFinal());
      return;
    }

    int length = ciphertext.length - start;

    switch (r.nextInt(4)) {
      case 0:
        baos.write(cipher.doFinal(ciphertext, start, length));
        break;
      case 1:
        baos.write(cipher.doFinal(Arrays.copyOfRange(ciphertext, start, ciphertext.length)));
        break;
      case 2:
        {
          int offset = r.nextInt(8);
          byte[] tmp = new byte[cipher.getOutputSize(length) + offset];
          int actualLength = cipher.doFinal(ciphertext, start, length, tmp, offset);
          baos.write(tmp, offset, actualLength);
          break;
        }
      case 3:
        {
          int resultSize = cipher.getOutputSize(length);
          ByteBuffer input = mungeBuffer(r, true, ciphertext, start, length);
          ByteBuffer output = mungeBuffer(r, false, new byte[resultSize], 0, resultSize);

          cipher.doFinal(input, output);
          assertByteBufferEmpty(input);

          output.flip();

          Channels.newChannel(baos).write(output);
          break;
        }
    }
  }

  private void applyDecryptUpdate(
      ByteArrayOutputStream baos, Random r, Cipher cipher, byte[] ciphertext, int start, int end)
      throws Exception {
    int length = end - start;

    switch (r.nextInt(4)) {
      case 0:
        baos.write(nullToEmpty(cipher.update(ciphertext, start, length)));
        break;
      case 1:
        baos.write(nullToEmpty(cipher.update(Arrays.copyOfRange(ciphertext, start, end))));
        break;
      case 2:
        {
          int offset = r.nextInt(8);
          byte[] tmp = new byte[cipher.getOutputSize(length) + offset];
          int actualLength = cipher.update(ciphertext, start, length, tmp, offset);
          baos.write(tmp, offset, actualLength);
          break;
        }
      case 3:
        {
          int resultSize = cipher.getOutputSize(length);
          if (resultSize < 0) {
            cipher.getOutputSize(length);
          }
          ByteBuffer input = mungeBuffer(r, true, ciphertext, start, length);
          ByteBuffer output = mungeBuffer(r, false, new byte[resultSize], 0, resultSize);

          cipher.update(input, output);
          assertByteBufferEmpty(input);

          output.flip();

          Channels.newChannel(baos).write(output);
          break;
        }
    }
  }

  private void applyAAD(Random r, Cipher cipher, byte[] aadData, int start, int end) {
    switch (r.nextInt(3)) {
      case 0:
        // Apply byte array directly
        cipher.updateAAD(aadData, start, end - start);
        break;
      case 1:
        // Apply wrapped byte buffer
        final ByteBuffer mungedBuffer = mungeBuffer(r, true, aadData, start, end - start);
        cipher.updateAAD(mungedBuffer);
        assertByteBufferEmpty(mungedBuffer);
        break;
      case 2:
        // Apply byte array copy
        cipher.updateAAD(Arrays.copyOfRange(aadData, start, end));
        break;
    }
  }

  private ByteBuffer mungeBuffer(
      Random r, boolean readOnlyAllowed, byte[] data, int start, int length) {
    ByteBuffer buf;
    switch (r.nextInt(3)) {
      case 0:
        buf = ByteBuffer.wrap(data, start, length);
        break;
      case 1:
        buf = ByteBuffer.allocateDirect(length);
        buf.put(data, start, length);
        buf.flip();
        break;
      case 2:
        buf = ByteBuffer.allocate(length);
        buf.put(data, start, length);
        buf.flip();
        break;
      default:
        throw new UnsupportedOperationException();
    }

    buf = buf.slice();

    if (readOnlyAllowed && r.nextBoolean()) {
      buf = buf.asReadOnlyBuffer();
    }

    return buf;
  }

  private int[] builtSplitArray(Random r, int count, int length) {
    int[] array = new int[count];

    for (int i = 0; i < array.length; i++) {
      int prevEnd = (i == 0) ? 0 : array[i - 1];
      if (prevEnd == length) {
        array[i] = length;
      } else {
        array[i] = prevEnd + r.nextInt(length - prevEnd);
      }
    }

    return array;
  }

  private byte[] nullToEmpty(byte[] buf) {
    if (buf == null) return new byte[0];
    return buf;
  }

  private void byteBufferDoFinal(
      boolean nativeOutput, Cipher cipher, OutputStream ciphertextStream, ByteBuffer finalData)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, IOException {
    ByteBuffer out =
        nativeOutput
            ? ByteBuffer.allocate(cipher.getOutputSize(finalData.remaining()))
            : ByteBuffer.allocateDirect(cipher.getOutputSize(finalData.remaining()));
    final ByteBuffer workingBuf = finalData.duplicate();
    cipher.doFinal(workingBuf, out);
    assertByteBufferEmpty(workingBuf);
    out.flip();
    Channels.newChannel(ciphertextStream).write(out);
  }

  private ByteBuffer getBuffer(Random r, boolean isNative, boolean isReadOnly, int bufferLength) {
    int beforePad = r.nextBoolean() ? r.nextInt(BUF_SIZE_SPREAD) : 0;
    int afterPad = r.nextBoolean() ? r.nextInt(BUF_SIZE_SPREAD) : 0;
    int totalSize = beforePad + bufferLength + afterPad;

    ByteBuffer buf =
        isNative ? ByteBuffer.allocateDirect(totalSize) : ByteBuffer.allocate(totalSize);

    buf.position(beforePad);
    buf.mark();
    buf.limit(beforePad + bufferLength);

    byte[] randBuf = new byte[bufferLength];
    r.nextBytes(randBuf);

    buf.duplicate().put(randBuf);

    return isReadOnly ? buf.asReadOnlyBuffer() : buf;
  }

  private static void assertByteBufferEmpty(final ByteBuffer buff) {
    assertEquals(
        buff.limit(),
        buff.position(),
        "ByteBuffer has remaining data when it should all be processed.");
  }
}
