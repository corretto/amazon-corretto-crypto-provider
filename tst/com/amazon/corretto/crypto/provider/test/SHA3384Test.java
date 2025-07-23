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
public class SHA3384Test {

  private static final String SHA3_384 = "SHA3-384";

  private MessageDigest getDigest() throws Exception {
    return MessageDigest.getInstance(SHA3_384, TestUtil.NATIVE_PROVIDER);
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
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
                .toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(
        Hex.decodeHex(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
                .toCharArray()),
        digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(
        Hex.decodeHex(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update("testing".getBytes());

    assertArrayEquals(
        Hex.decodeHex(
            "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(
        Hex.decodeHex(
            "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005"
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
            "e15a44d4e12ac138db4b8d77e954d78d94de4391ec2d1d8b2b8ace1a2f4b3d2fb9efd0546d6fcafacbe5b1640639b005"
                .toCharArray()),
        digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    //SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_384).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    //SHA3 is not exposed in SUN JDK8, so we can't test against it
    TestUtil.assumeMinimumJavaVersion(11);
    new HashFunctionTester(SHA3_384).testAPI();
  }

  @Test
  public void cavpShortVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_384ShortMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_384).test(RspTestEntry.iterateOverResource(is));
    }
  }

  @Test
  public void cavpLongVectors() throws Throwable {
    try (final InputStream is =
        new GZIPInputStream(TestUtil.getTestData("SHA3_384LongMsg.rsp.gz"))) {
      new HashFunctionTester(SHA3_384).test(RspTestEntry.iterateOverResource(is));
    }
  }
}
