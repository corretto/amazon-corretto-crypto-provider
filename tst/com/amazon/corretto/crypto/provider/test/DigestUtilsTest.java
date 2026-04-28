// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.utils.DigestUtils;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class DigestUtilsTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  // Expected DigestInfo DER prefixes per RFC 8017 Sec. 9.2 Note 1. Output of digestInfoWrap
  // must be prefix || digest bytes.
  private static final byte[] SHA1_PREFIX = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
  };
  private static final byte[] SHA256_PREFIX = {
    0x30,
    0x31,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    (byte) 0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x01,
    0x05,
    0x00,
    0x04,
    0x20
  };
  private static final byte[] SHA384_PREFIX = {
    0x30,
    0x41,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    (byte) 0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x02,
    0x05,
    0x00,
    0x04,
    0x30
  };
  private static final byte[] SHA512_PREFIX = {
    0x30,
    0x51,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    (byte) 0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x03,
    0x05,
    0x00,
    0x04,
    0x40
  };
  private static final byte[] SHA512_256_PREFIX = {
    0x30,
    0x31,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    (byte) 0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x06,
    0x05,
    0x00,
    0x04,
    0x20
  };

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  @Test
  public void testSha256() throws Exception {
    byte[] digest =
        MessageDigest.getInstance("SHA-256", NATIVE_PROVIDER).digest("hello".getBytes());
    byte[] wrapped = DigestUtils.digestInfoWrap("SHA-256", digest);
    assertArrayEquals(concat(SHA256_PREFIX, digest), wrapped);
    assertEquals(digest.length + 19, wrapped.length);
  }

  @Test
  public void testSha1() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-1", NATIVE_PROVIDER).digest("hello".getBytes());
    byte[] wrapped = DigestUtils.digestInfoWrap("SHA-1", digest);
    assertArrayEquals(concat(SHA1_PREFIX, digest), wrapped);
    assertEquals(digest.length + 15, wrapped.length);
  }

  @Test
  public void testSha384() throws Exception {
    byte[] digest =
        MessageDigest.getInstance("SHA-384", NATIVE_PROVIDER).digest("hello".getBytes());
    byte[] wrapped = DigestUtils.digestInfoWrap("SHA-384", digest);
    assertArrayEquals(concat(SHA384_PREFIX, digest), wrapped);
  }

  @Test
  public void testSha512() throws Exception {
    byte[] digest =
        MessageDigest.getInstance("SHA-512", NATIVE_PROVIDER).digest("hello".getBytes());
    byte[] wrapped = DigestUtils.digestInfoWrap("SHA-512", digest);
    assertArrayEquals(concat(SHA512_PREFIX, digest), wrapped);
  }

  @Test
  public void testSha512Trunc256() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-512/256").digest("hello".getBytes());
    byte[] wrapped = DigestUtils.digestInfoWrap("SHA-512/256", digest);
    assertArrayEquals(concat(SHA512_256_PREFIX, digest), wrapped);
  }

  @Test
  public void testNullDigestName() {
    assertThrows(
        IllegalArgumentException.class, () -> DigestUtils.digestInfoWrap(null, new byte[32]));
  }

  @Test
  public void testNullDigestBytes() {
    assertThrows(IllegalArgumentException.class, () -> DigestUtils.digestInfoWrap("SHA-256", null));
  }

  @Test
  public void testUnsupportedDigestName() {
    assertThrows(
        IllegalArgumentException.class,
        () -> DigestUtils.digestInfoWrap("NO-SUCH-DIGEST", new byte[32]));
  }

  @Test
  public void testWrongDigestLength() {
    byte[] tooShort = new byte[16];
    Arrays.fill(tooShort, (byte) 0xaa);
    assertThrows(
        IllegalArgumentException.class, () -> DigestUtils.digestInfoWrap("SHA-256", tooShort));

    byte[] tooLong = new byte[64];
    Arrays.fill(tooLong, (byte) 0xbb);
    assertThrows(
        IllegalArgumentException.class, () -> DigestUtils.digestInfoWrap("SHA-256", tooLong));
  }
}
