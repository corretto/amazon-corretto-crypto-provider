// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfExpandSpec;
import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfExtractSpec;
import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfSpec;
import static com.amazon.corretto.crypto.provider.test.TestUtil.EMPTY_ARRAY;
import static com.amazon.corretto.crypto.provider.test.TestUtil.decodeHex;
import static com.amazon.corretto.crypto.provider.test.TestUtil.getHkdfSecretKeyFactory;
import static com.amazon.corretto.crypto.provider.test.TestUtil.intArrayToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HkdfKatTest {

  @Test
  public void checkKatTests() throws InvalidKeySpecException {
    for (TestCase tc : testCases) {
      tc.checkTestCase();
    }
  }

  // These tests are from
  // https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/hkdf/hkdf_test.cc
  private static TestCase[] testCases = {
    new TestCase("EMPTY 0", "HmacSHA256", 10).setKey("eb70f01dede9afafa449"),
    new TestCase("EMPTY 1", "HmacSHA256", 100)
        .setKey(
            "eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe181e59c2ec0fe6e7e7ac2613b6ab65342a83379969da234240cded3777914db9075568c74fdb8fc92331d5c59e1e2dd77a8c2c63aba7cf2d3457f8ee8620462f8ad77a798b"),
    new TestCase("RFC 5869 1", "HmacSHA256", 42)
        .setIkm(
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b)
        .setSalt(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c)
        .setInfo(0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9)
        .setPrk(
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5)
        .setKey(
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65),
    new TestCase("RFC 5869 2", "HmacSHA256", 82)
        .setIkm(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f)
        .setSalt(
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf)
        .setInfo(
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff)
        .setPrk(
            0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35,
            0xb4, 0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40,
            0xc1, 0x5f, 0xc2, 0x44)
        .setKey(
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87),
    new TestCase("RFC 5869 3", "HmacSHA256", 42)
        .setIkm(
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b)
        .setPrk(
            0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64,
            0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c,
            0x29, 0x3c, 0xcb, 0x04)
        .setKey(
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8),
    new TestCase("RFC 5869 4", "HmacSHA1", 42)
        .setIkm(0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b)
        .setSalt(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c)
        .setInfo(0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9)
        .setPrk(
            0x9b, 0x6c, 0x18, 0xc4, 0x32, 0xa7, 0xbf, 0x8f, 0x0e, 0x71, 0xc8, 0xeb, 0x88, 0xf4,
            0xb3, 0x0b, 0xaa, 0x2b, 0xa2, 0x43)
        .setKey(
            0x08, 0x5a, 0x01, 0xea, 0x1b, 0x10, 0xf3, 0x69, 0x33, 0x06, 0x8b, 0x56, 0xef, 0xa5,
            0xad, 0x81, 0xa4, 0xf1, 0x4b, 0x82, 0x2f, 0x5b, 0x09, 0x15, 0x68, 0xa9, 0xcd, 0xd4,
            0xf1, 0x55, 0xfd, 0xa2, 0xc2, 0x2e, 0x42, 0x24, 0x78, 0xd3, 0x05, 0xf3, 0xf8, 0x96),
    new TestCase("RFC 5869 5", "HmacSHA1", 82)
        .setIkm(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f)
        .setSalt(
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf)
        .setInfo(
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff)
        .setPrk(
            0x8a, 0xda, 0xe0, 0x9a, 0x2a, 0x30, 0x70, 0x59, 0x47, 0x8d, 0x30, 0x9b, 0x26, 0xc4,
            0x11, 0x5a, 0x22, 0x4c, 0xfa, 0xf6)
        .setKey(
            0x0b, 0xd7, 0x70, 0xa7, 0x4d, 0x11, 0x60, 0xf7, 0xc9, 0xf1, 0x2c, 0xd5, 0x91, 0x2a,
            0x06, 0xeb, 0xff, 0x6a, 0xdc, 0xae, 0x89, 0x9d, 0x92, 0x19, 0x1f, 0xe4, 0x30, 0x56,
            0x73, 0xba, 0x2f, 0xfe, 0x8f, 0xa3, 0xf1, 0xa4, 0xe5, 0xad, 0x79, 0xf3, 0xf3, 0x34,
            0xb3, 0xb2, 0x02, 0xb2, 0x17, 0x3c, 0x48, 0x6e, 0xa3, 0x7c, 0xe3, 0xd3, 0x97, 0xed,
            0x03, 0x4c, 0x7f, 0x9d, 0xfe, 0xb1, 0x5c, 0x5e, 0x92, 0x73, 0x36, 0xd0, 0x44, 0x1f,
            0x4c, 0x43, 0x00, 0xe2, 0xcf, 0xf0, 0xd0, 0x90, 0x0b, 0x52, 0xd3, 0xb4),
    new TestCase("RFC 5869 6", "HmacSHA1", 42)
        .setIkm(
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b)
        .setPrk(
            0xda, 0x8c, 0x8a, 0x73, 0xc7, 0xfa, 0x77, 0x28, 0x8e, 0xc6, 0xf5, 0xe7, 0xc2, 0x97,
            0x78, 0x6a, 0xa0, 0xd3, 0x2d, 0x01)
        .setKey(
            0x0a, 0xc1, 0xaf, 0x70, 0x02, 0xb3, 0xd7, 0x61, 0xd1, 0xe5, 0x52, 0x98, 0xda, 0x9d,
            0x05, 0x06, 0xb9, 0xae, 0x52, 0x05, 0x72, 0x20, 0xa3, 0x06, 0xe0, 0x7b, 0x6b, 0x87,
            0xe8, 0xdf, 0x21, 0xd0, 0xea, 0x00, 0x03, 0x3d, 0xe0, 0x39, 0x84, 0xd3, 0x49, 0x18),
    new TestCase("RFC 5869 7", "HmacSHA1", 42)
        .setIkm(
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
            0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c)
        .setPrk(
            0x2a, 0xdc, 0xca, 0xda, 0x18, 0x77, 0x9e, 0x7c, 0x20, 0x77, 0xad, 0x2e, 0xb1, 0x9d,
            0x3f, 0x3e, 0x73, 0x13, 0x85, 0xdd)
        .setKey(
            0x2c, 0x91, 0x11, 0x72, 0x04, 0xd7, 0x45, 0xf3, 0x50, 0x0d, 0x63, 0x6a, 0x62, 0xf6,
            0x4f, 0x0a, 0xb3, 0xba, 0xe5, 0x48, 0xaa, 0x53, 0xd4, 0x23, 0xb0, 0xd1, 0xf2, 0x7e,
            0xbb, 0xa6, 0xf5, 0xe5, 0x67, 0x3a, 0x08, 0x1d, 0x70, 0xcc, 0xe7, 0xac, 0xfc, 0x48),
    new TestCase("wycheproof_testvectors SHA-384 1", "HmacSHA384", 20)
        .setIkm("60ab7f45b0ad534683b3a6c020d4f775")
        .setKey("3f8b0e4a7b2bff01a26a18f1e07c0218897a324e"),
    new TestCase("wycheproof_testvectors SHA-512 1", "HmacSHA512", 20)
        .setIkm("60ab7f45b0ad534683b3a6c020d4f775")
        .setKey("2109bd244744acae2b8caa9e70f57596ad680212")
  };

  private static class TestCase {
    String id;
    String digest;
    byte[] ikm = EMPTY_ARRAY;
    byte[] salt = EMPTY_ARRAY;
    byte[] info = EMPTY_ARRAY;
    int keyLen;
    byte[] prk;
    byte[] key;

    TestCase(String id, String digest, int keyLen) {
      this.id = id;
      this.digest = digest;
      this.keyLen = keyLen;
    }

    void checkTestCase() throws InvalidKeySpecException {
      final SecretKeyFactory skf = getHkdfSecretKeyFactory(digest);
      final KeySpec hkdfSpec = hkdfSpec(ikm, salt, info, keyLen, null);
      final byte[] actualKey1 = skf.generateSecret(hkdfSpec).getEncoded();
      assertEquals("keyLen test a - " + id, keyLen, actualKey1.length);
      if (key != null) {
        assertArrayEquals("key test a - " + id, key, actualKey1);
      }

      final KeySpec hkdfExtractSpec = hkdfExtractSpec(ikm, salt, null);
      final byte[] actualPrk = skf.generateSecret(hkdfExtractSpec).getEncoded();
      if (prk != null) {
        assertArrayEquals("prk test - " + id, prk, actualPrk);
      }

      final KeySpec hkdfExpandSpec = hkdfExpandSpec(actualPrk, info, keyLen, null);
      final byte[] actualKey2 = skf.generateSecret(hkdfExpandSpec).getEncoded();
      assertEquals("keyLen test b - " + id, keyLen, actualKey2.length);

      assertArrayEquals("key test b - " + id, actualKey1, actualKey2);
    }

    TestCase setIkm(int... values) {
      this.ikm = intArrayToByteArray(values);
      return this;
    }

    TestCase setIkm(String hexValue) {
      this.ikm = decodeHex(hexValue);
      return this;
    }

    TestCase setSalt(int... values) {
      this.salt = intArrayToByteArray(values);
      return this;
    }

    TestCase setSalt(String hexValue) {
      this.salt = decodeHex(hexValue);
      return this;
    }

    TestCase setInfo(int... values) {
      this.info = intArrayToByteArray(values);
      return this;
    }

    TestCase setInfo(String hexValue) {
      this.info = decodeHex(hexValue);
      return this;
    }

    TestCase setPrk(int... values) {
      this.prk = intArrayToByteArray(values);
      return this;
    }

    TestCase setPrk(String hexValue) {
      this.prk = decodeHex(hexValue);
      return this;
    }

    TestCase setKey(int... values) {
      this.key = intArrayToByteArray(values);
      return this;
    }

    TestCase setKey(String hexValue) {
      this.key = decodeHex(hexValue);
      return this;
    }
  }
}
