// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPInputStream;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class AesGcmKatTest {

  private static final boolean tagFilter(final RspTestEntry entry) {
    final int tagLenBits = Integer.parseInt(entry.getHeader("Taglen"));
    return tagLenBits > 96;
  }

  private static Stream<RspTestEntry> getEntriesFromFile(final String fileName) throws IOException {
    final File rsp = new File(System.getProperty("test.data.dir"), fileName);
    final InputStream is = new GZIPInputStream(new FileInputStream(rsp));
    final Iterator<RspTestEntry> iterator =
        RspTestEntry.iterateOverResource(is, true); // Auto-closes stream
    final Spliterator<RspTestEntry> split =
        Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED);
    return StreamSupport.stream(split, false).filter(AesGcmKatTest::tagFilter);
  }

  public static Stream<RspTestEntry> encrypt128Params() throws IOException {
    return getEntriesFromFile("gcmEncryptExtIV128.rsp.gz");
  }

  public static Stream<RspTestEntry> encrypt256Params() throws IOException {
    return getEntriesFromFile("gcmEncryptExtIV256.rsp.gz");
  }

  public static Stream<RspTestEntry> decrypt128Params() throws IOException {
    return getEntriesFromFile("gcmDecrypt128.rsp.gz");
  }

  public static Stream<RspTestEntry> decrypt256Params() throws IOException {
    return getEntriesFromFile("gcmDecrypt256.rsp.gz");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("encrypt128Params")
  public void encrypt128(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("decrypt256Params")
  public void decrypt256(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("decrypt128Params")
  public void decrypt128(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("encrypt256Params")
  public void encrypt256(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  private void singleTest(final RspTestEntry entry)
      throws GeneralSecurityException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException {
    final int tagLenBits = Integer.parseInt(entry.getHeader("Taglen"));
    final SecretKey key = new SecretKeySpec(entry.getInstanceFromHex("Key"), "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(tagLenBits, entry.getInstanceFromHex("IV"));
    final byte[] expectedPT = entry.getInstanceFromHex("PT");
    final byte[] expectedCT = entry.getInstanceFromHex("CT");
    final byte[] aad = entry.getInstanceFromHex("AAD");
    final byte[] tag = entry.getInstanceFromHex("Tag");
    final byte[] expectedCtCombined = Arrays.copyOf(expectedCT, expectedCT.length + tag.length);
    final boolean expectSuccess = !entry.getInstance().containsKey("FAIL");
    System.arraycopy(tag, 0, expectedCtCombined, expectedCT.length, tag.length);

    Cipher c = getCipher();

    if (expectSuccess) {
      c.init(Cipher.ENCRYPT_MODE, key, spec);

      c.updateAAD(aad);
      final byte[] ct = c.doFinal(expectedPT);
      assertArraysHexEquals(expectedCtCombined, ct);
    }

    c.init(Cipher.DECRYPT_MODE, key, spec);
    try {
      c.updateAAD(aad);
      final byte[] pt = c.doFinal(expectedCtCombined);
      assertTrue("Successful decryption expected", expectSuccess);
      assertArraysHexEquals(expectedPT, pt);
    } catch (final AEADBadTagException ex) {
      assertFalse("Failed decryption expected", expectSuccess);
    }
  }

  private static Cipher getCipher() throws GeneralSecurityException {
    return Cipher.getInstance("AES/GCM/NoPadding", TestUtil.NATIVE_PROVIDER);
  }
}
