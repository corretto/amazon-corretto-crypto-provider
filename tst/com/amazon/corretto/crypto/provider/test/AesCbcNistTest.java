// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.getEntriesFromFile;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.function.Function;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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
public class AesCbcNistTest {

  @ParameterizedTest(name = "{0}")
  @MethodSource("allCbcKatTests")
  public void cbcKatTests(final RspTestEntry entry) throws Exception {
    singleTest(entry);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("allCbcMmtTests")
  public void cbcMmtTests(final RspTestEntry entry) throws Exception {
    singleTest(entry);
  }

  // These tests are coming from the following URL:
  // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers
  private static Stream<RspTestEntry> allCbcKatTests() throws Exception {
    return Stream.of(
            getEntriesFromFile("CBCGFSbox128.rsp.gz"),
            getEntriesFromFile("CBCGFSbox192.rsp.gz"),
            getEntriesFromFile("CBCGFSbox256.rsp.gz"),
            getEntriesFromFile("CBCKeySbox128.rsp.gz"),
            getEntriesFromFile("CBCKeySbox192.rsp.gz"),
            getEntriesFromFile("CBCKeySbox256.rsp.gz"),
            getEntriesFromFile("CBCVarKey128.rsp.gz"),
            getEntriesFromFile("CBCVarKey192.rsp.gz"),
            getEntriesFromFile("CBCVarKey256.rsp.gz"),
            getEntriesFromFile("CBCVarTxt128.rsp.gz"),
            getEntriesFromFile("CBCVarTxt192.rsp.gz"),
            getEntriesFromFile("CBCVarTxt256.rsp.gz"))
        .flatMap(Function.identity());
  }

  private static Stream<RspTestEntry> allCbcMmtTests() throws Exception {
    return Stream.of(
            getEntriesFromFile("CBCMMT128.rsp.gz"),
            getEntriesFromFile("CBCMMT192.rsp.gz"),
            getEntriesFromFile("CBCMMT256.rsp.gz"))
        .flatMap(Function.identity());
  }

  private static void singleTest(final RspTestEntry entry) throws Exception {
    final SecretKey key = new SecretKeySpec(entry.getInstanceFromHex("KEY"), "AES");
    final IvParameterSpec iv = new IvParameterSpec(entry.getInstanceFromHex("IV"));
    final byte[] plainText = entry.getInstanceFromHex("PLAINTEXT");
    final byte[] ciphertexts = entry.getInstanceFromHex("CIPHERTEXT");
    final Cipher cipher = AesCbcTest.accpAesCbcCipher(false);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    assertArrayEquals(ciphertexts, cipher.doFinal(plainText));
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    assertArrayEquals(plainText, cipher.doFinal(ciphertexts));
  }
}
