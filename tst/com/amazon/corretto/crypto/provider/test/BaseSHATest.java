// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
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

  private final String algorithm;
  private final String nullDigest;
  private final byte[] preimage;
  private final String testVector;
  private final List<String> cavpFiles;

  /**
   * @param algorithm the JCA standard name of the digest under test
   * @param nullDigest hex-encoded digest of the empty input
   * @param preimage the input whose digest is {@code testVector}
   * @param testVector hex-encoded digest of {@code preimage}
   * @param cavpFiles gzipped CAVP response files (short and long message vectors)
   */
  protected BaseSHATest(
      final String algorithm,
      final String nullDigest,
      final String preimage,
      final String testVector,
      final String... cavpFiles) {
    this.algorithm = algorithm;
    this.nullDigest = nullDigest;
    this.preimage = preimage.getBytes(StandardCharsets.UTF_8);
    this.testVector = testVector;
    this.cavpFiles = Arrays.asList(cavpFiles);
  }

  protected MessageDigest getDigest() throws Exception {
    return MessageDigest.getInstance(algorithm, TestUtil.NATIVE_PROVIDER);
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
    assertArrayEquals(Hex.decodeHex(nullDigest.toCharArray()), digest.digest());
    digest = getDigest();
    digest.update(new byte[0]);
    assertArrayEquals(Hex.decodeHex(nullDigest.toCharArray()), digest.digest());
    digest = getDigest();
    digest.update(ByteBuffer.allocateDirect(0));
    assertArrayEquals(Hex.decodeHex(nullDigest.toCharArray()), digest.digest());
  }

  @Test
  public void testVector() throws Exception {
    MessageDigest digest = getDigest();
    digest.update(preimage);

    assertArrayEquals(Hex.decodeHex(testVector.toCharArray()), digest.digest());
  }

  @Test
  public void testFastPath() throws Exception {
    MessageDigest digest = getDigest();

    assertArrayEquals(Hex.decodeHex(testVector.toCharArray()), digest.digest(preimage));
  }

  @Test
  public void testNativeByteBuffer() throws Exception {
    ByteBuffer nativeBuf = ByteBuffer.allocateDirect(preimage.length);
    nativeBuf.put(preimage);
    nativeBuf.flip();

    MessageDigest digest = getDigest();
    digest.update(nativeBuf);
    assertEquals(nativeBuf.position(), nativeBuf.limit());

    assertArrayEquals(Hex.decodeHex(testVector.toCharArray()), digest.digest());
  }

  @Test
  public void testRandomly() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (algorithm.startsWith("SHA3")) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(algorithm).testRandomly(1000);
  }

  @Test
  public void testAPIDetails() throws Exception {
    // SHA3 is not exposed in SUN JDK8, so we can't test against it
    if (algorithm.startsWith("SHA3")) {
      TestUtil.assumeMinimumJavaVersion(11);
    }
    new HashFunctionTester(algorithm).testAPI();
  }

  @Test
  public void cavpVectors() throws Throwable {
    for (final String cavpFile : cavpFiles) {
      try (final InputStream is = new GZIPInputStream(TestUtil.getTestData(cavpFile))) {
        new HashFunctionTester(algorithm).test(RspTestEntry.iterateOverResource(is));
      }
    }
  }
}
