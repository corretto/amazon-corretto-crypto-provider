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
public class SHA3224Test {

  private static final String SHA3_224 = "SHA3-224";

  private MessageDigest getDigest() throws Exception {
    return MessageDigest.getInstance(SHA3_224, TestUtil.NATIVE_PROVIDER);
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
        Hex.decodeHex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7".toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(
        Hex.decodeHex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7".toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(
        Hex.decodeHex("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7".toCharArray()),
        digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update("testing".getBytes());

    assertArrayEquals(
        Hex.decodeHex("04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51".toCharArray()),
        digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(
        Hex.decodeHex("04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51".toCharArray()),
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
        Hex.decodeHex("04eaf0c175aa45299155aca3f97e41c2d684eb0978c9af6cd88c5a51".toCharArray()),
        digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_224).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_224).testAPI();
  }

  @Test
  public void cavpShortVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_224ShortMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_224).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @Test
  public void cavpLongVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_224LongMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_224).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
