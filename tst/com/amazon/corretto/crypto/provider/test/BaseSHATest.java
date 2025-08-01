// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.zip.GZIPInputStream;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_REFLECTION)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public abstract class BaseSHATest {

  protected abstract String getAlgorithm();

  protected abstract String getNullDigest();

  protected abstract String getTestVector();

  protected abstract String getCavpShortFile();

  protected abstract String getCavpLongFile();

  protected MessageDigest getDigest() throws Exception {
    System.out.print(getAlgorithm());
    return MessageDigest.getInstance(getAlgorithm(), TestUtil.NATIVE_PROVIDER);
  }

  @Test
  public void testNegativeLength() throws Exception {
    final byte[] data = new byte[32];
    final int start = 0;
    final int end = -31;

    final MessageDigest digest = getDigest();

    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          digest.update(data, start, end);
        });
  }

  @Test
  public void testNullDigest() throws Exception {
    MessageDigest digest = getDigest();
    assertArrayEquals(Hex.decodeHex(getNullDigest().toCharArray()), digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(Hex.decodeHex(getNullDigest().toCharArray()), digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(Hex.decodeHex(getNullDigest().toCharArray()), digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update("testing".getBytes());

    assertArrayEquals(Hex.decodeHex(getTestVector().toCharArray()), digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(
        Hex.decodeHex(getTestVector().toCharArray()), digest.digest("testing".getBytes()));
  }

  @Test
  public void testNativeByteBuffer() throws Exception {
    byte[] testData = "testing".getBytes();
    ByteBuffer nativeBuf = ByteBuffer.allocateDirect(testData.length);
    nativeBuf.put(testData);
    nativeBuf.flip();

    MessageDigest digest = getDigest();
    digest.update(nativeBuf);
    assertEquals(nativeBuf.position(), nativeBuf.limit());

    assertArrayEquals(Hex.decodeHex(getTestVector().toCharArray()), digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (getAlgorithm().startsWith("SHA3")) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(getAlgorithm()).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (getAlgorithm().startsWith("SHA3")) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(getAlgorithm()).testAPI();
  }

  @Test
  public void cavpShortVectors() throws Throwable {
    try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(getCavpShortFile()))) {
      new HashFunctionTester(getAlgorithm()).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @Test
  public void cavpLongVectors() throws Throwable {
    try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(getCavpLongFile()))) {
      new HashFunctionTester(getAlgorithm()).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
