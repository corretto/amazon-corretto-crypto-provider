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
public class SHA3_256Test {

  private static final String SHA3_256 = "SHA3-256";

  private MessageDigest getDigest() throws Exception {
    return MessageDigest.getInstance(SHA3_256, TestUtil.NATIVE_PROVIDER);
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
    assertArrayEquals(
        Hex.decodeHex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(
        Hex.decodeHex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(
        Hex.decodeHex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".toCharArray()),
        digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update("testing".getBytes());

    assertArrayEquals(
        Hex.decodeHex(
            "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e".toCharArray()),
        digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(
        Hex.decodeHex(
            "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e".toCharArray()),
        digest.digest("testing".getBytes()));
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

    assertArrayEquals(
        Hex.decodeHex(
            "7f5979fb78f082e8b1c676635db8795c4ac6faba03525fb708cb5fd68fd40c5e".toCharArray()),
        digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    new HashFunctionTester(SHA3_256).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    new HashFunctionTester(SHA3_256).testAPI();
  }

  @Test
  public void cavpShortVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData(""))) {
      new HashFunctionTester(SHA3_256).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @Test
  public void cavpLongVectors() throws Throwable {
    try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(""))) {
      new HashFunctionTester(SHA3_256).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
