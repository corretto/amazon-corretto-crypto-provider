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
public class SHA3512Test {

  private static final String SHA3_512 = "SHA3-512";

  private MessageDigest getDigest() throws Exception {
    return MessageDigest.getInstance(SHA3_512, TestUtil.NATIVE_PROVIDER);
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
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(
        Hex.decodeHex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(
        Hex.decodeHex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update("testing".getBytes());

    assertArrayEquals(
        Hex.decodeHex(
            "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(
        Hex.decodeHex(
            "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1"
                .toCharArray()),
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
            "881c7d6ba98678bcd96e253086c4048c3ea15306d0d13ff48341c6285ee71102a47b6f16e20e4d65c0c3d677be689dfda6d326695609cbadfafa1800e9eb7fc1"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_512).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_512).testAPI();
  }

  @Test
  public void cavpShortVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_512ShortMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_512).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @Test
  public void cavpLongVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_512LongMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_512).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
