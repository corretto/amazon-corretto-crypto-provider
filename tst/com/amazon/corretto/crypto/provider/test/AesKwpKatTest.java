// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
public final class AesKwpKatTest {

  public static Stream<RspTestEntry> encrypt128Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpEncrypt128.rsp.gz");
  }

  public static Stream<RspTestEntry> decrypt128Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpDecrypt128.rsp.gz");
  }

  public static Stream<RspTestEntry> encrypt192Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpEncrypt192.rsp.gz");
  }

  public static Stream<RspTestEntry> decrypt192Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpDecrypt192.rsp.gz");
  }

  public static Stream<RspTestEntry> encrypt256Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpEncrypt256.rsp.gz");
  }

  public static Stream<RspTestEntry> decrypt256Params() throws IOException {
    return TestUtil.getEntriesFromFile("kwpDecrypt256.rsp.gz");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("encrypt128Params")
  public void encrypt128(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("decrypt128Params")
  public void decrypt128(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("encrypt192Params")
  public void encrypt192(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("decrypt192Params")
  public void decrypt192(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("encrypt256Params")
  public void encrypt256(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("decrypt256Params")
  public void decrypt256(final RspTestEntry entry) throws GeneralSecurityException {
    singleTest(entry);
  }

  private void singleTest(final RspTestEntry entry)
      throws GeneralSecurityException,
          InvalidKeyException,
          InvalidAlgorithmParameterException,
          IllegalBlockSizeException,
          BadPaddingException {
    final SecretKey key = new SecretKeySpec(entry.getInstanceFromHex("K"), "AES");
    final byte[] expectedPT = entry.getInstanceFromHex("P");
    final byte[] expectedCT = entry.getInstanceFromHex("C");
    final boolean expectSuccess = !entry.getInstance().containsKey("FAIL");

    Cipher c = getCipher();

    if (expectSuccess) {
      c.init(Cipher.ENCRYPT_MODE, key);

      final byte[] ct = c.doFinal(expectedPT);
      assertArraysHexEquals(expectedCT, ct);
    }

    c.init(Cipher.DECRYPT_MODE, key);
    try {
      final byte[] pt = c.doFinal(expectedCT);
      assertTrue("Successful decryption expected", expectSuccess);
      assertArraysHexEquals(expectedPT, pt);
    } catch (RuntimeCryptoException e) {
      assertFalse("Failed decryption expected", expectSuccess);
    }
  }

  private static Cipher getCipher() throws GeneralSecurityException {
    return Cipher.getInstance("AES/KWP/NoPadding", TestUtil.NATIVE_PROVIDER);
  }
}
