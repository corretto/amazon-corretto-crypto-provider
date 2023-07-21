// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfExpandSpec;
import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfExtractSpec;
import static com.amazon.corretto.crypto.provider.HkdfSpec.hkdfSpec;
import static com.amazon.corretto.crypto.provider.test.TestUtil.EMPTY_ARRAY;
import static com.amazon.corretto.crypto.provider.test.TestUtil.getHkdfSecretKeyFactory;
import static com.amazon.corretto.crypto.provider.test.TestUtil.intArrayIsEqualToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.amazon.corretto.crypto.provider.HkdfSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HkdfTest {
  @Test
  public void sampleUsage1() throws InvalidKeySpecException {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA256");
    final byte[] secret = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    final byte[] salt = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    final byte[] info = {
      (byte) 0xf0,
      (byte) 0xf1,
      (byte) 0xf2,
      (byte) 0xf3,
      (byte) 0xf4,
      (byte) 0xf5,
      (byte) 0xf6,
      (byte) 0xf7,
      (byte) 0xf8,
      (byte) 0xf9
    };
    final KeySpec keySpec = hkdfSpec(secret, salt, info, 42, "My42ByteSecretKey");
    final SecretKey sk = skf.generateSecret(keySpec);
    assertTrue(sk instanceof SecretKeySpec);
    final SecretKeySpec sks = (SecretKeySpec) sk;
    final byte[] output1 = sks.getEncoded();
    assertEquals(42, output1.length);
    final int[] expectedOutput = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
      0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
      0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
      0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
    };
    assertTrue(intArrayIsEqualToByteArray(expectedOutput, output1));
    assertEquals("My42ByteSecretKey", sks.getAlgorithm());

    // Let's test the following equation
    // HKDF(secret, salt, info, keyLen) == HKDF_expand(HKDF_extract(secret, salt), info, keyLen)
    final KeySpec keySpecForExtract = hkdfExtractSpec(secret, salt, null);
    final int[] expectedPrk = {
      0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d,
      0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
      0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };
    final byte[] actualPrk = skf.generateSecret(keySpecForExtract).getEncoded();
    assertTrue(intArrayIsEqualToByteArray(expectedPrk, actualPrk));
    final KeySpec keySpecForExpand = hkdfExpandSpec(actualPrk, info, 42, null);
    final byte[] output2 = skf.generateSecret(keySpecForExpand).getEncoded();
    assertArrayEquals(output1, output2);
  }

  @Test
  public void sampleUsage2() throws InvalidKeySpecException {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA256");
    final byte[] secret = TestUtil.decodeHex("60ab7f45b0ad534683b3a6c020d4f775");
    final byte[] salt = EMPTY_ARRAY;
    final byte[] info = EMPTY_ARRAY;
    final KeySpec keySpec = hkdfSpec(secret, salt, info, 20, null);
    final SecretKey sk = skf.generateSecret(keySpec);
    assertTrue(sk instanceof SecretKeySpec);
    final SecretKeySpec sks = (SecretKeySpec) sk;
    final byte[] output1 = sks.getEncoded();
    assertEquals(20, output1.length);
    final byte[] expectedOutput = TestUtil.decodeHex("ae5dbce80bbab5bca5b3c6d3b7e6548fb2c23b2f");
    assertArrayEquals(expectedOutput, output1);
    assertEquals(HkdfSpec.DEFAULT_ALGORITHM_NAME, sks.getAlgorithm());

    // Let's test the following equation
    // HKDF(secret, salt, info, keyLen) == HKDF_expand(HKDF_extract(secret, salt), info, keyLen)
    final KeySpec keySpecForExtract = hkdfExtractSpec(secret, salt, null);
    final byte[] prk = skf.generateSecret(keySpecForExtract).getEncoded();
    final KeySpec keySpecForExpand = hkdfExpandSpec(prk, info, 20, null);
    final byte[] output2 = skf.generateSecret(keySpecForExpand).getEncoded();
    assertArrayEquals(output1, output2);
  }

  @Test
  public void testHkdfWithShortInputs() throws InvalidKeySpecException {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA256");
    for (int i = 0; i < 100; i++) {
      final byte[] input = new byte[i];
      for (byte j = 0; j != (byte) i; j++) {
        input[j] = j;
      }
      for (int keyLen = 1; keyLen != 100; keyLen++) {
        final KeySpec spec = hkdfSpec(input, input, input, keyLen, null);
        final byte[] key = skf.generateSecret(spec).getEncoded();
        assertEquals(keyLen, key.length);
      }
    }
  }

  @Test
  public void testHkdfExtractWithShortInputs() throws InvalidKeySpecException {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA256");
    for (int i = 0; i < 100; i++) {
      final byte[] input = new byte[i];
      for (byte j = 0; j != (byte) i; j++) {
        input[j] = j;
      }
      final KeySpec spec = hkdfExtractSpec(input, input, null);
      final byte[] key = skf.generateSecret(spec).getEncoded();
      assertEquals(32, key.length);
    }
  }

  @Test
  public void testHkdfExpandWithShortInputs() throws InvalidKeySpecException {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA256");
    for (int i = 0; i < 100; i++) {
      final byte[] input = new byte[i];
      for (byte j = 0; j != (byte) i; j++) {
        input[j] = j;
      }
      for (int keyLen = 1; keyLen != 100; keyLen++) {
        final KeySpec spec = hkdfExpandSpec(input, input, keyLen, null);
        final byte[] key = skf.generateSecret(spec).getEncoded();
        assertEquals(keyLen, key.length);
      }
    }
  }

  @Test
  public void invalidInputTests() {
    assertThrows(
        IllegalArgumentException.class,
        () -> hkdfSpec(EMPTY_ARRAY, EMPTY_ARRAY, EMPTY_ARRAY, -1, null));

    assertThrows(IllegalArgumentException.class, () -> HkdfSpec.builder().withMode(0).build());
    assertThrows(IllegalArgumentException.class, () -> HkdfSpec.builder().withMode(4).build());

    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA1");
    final SecretKeySpec sks = new SecretKeySpec(new byte[16], "AES");
    assertThrows(InvalidKeySpecException.class, () -> skf.generateSecret(sks));

    final KeySpec specLargeDesiredKey1 =
        hkdfSpec(EMPTY_ARRAY, EMPTY_ARRAY, EMPTY_ARRAY, 10000, null);
    final KeySpec specLargeDesiredKey2 =
        hkdfSpec(EMPTY_ARRAY, EMPTY_ARRAY, EMPTY_ARRAY, Integer.MAX_VALUE, null);
    assertThrows(IllegalArgumentException.class, () -> skf.generateSecret(specLargeDesiredKey1));
    assertThrows(IllegalArgumentException.class, () -> skf.generateSecret(specLargeDesiredKey2));
  }

  @Test
  public void unsupportedOperationsTests() {
    final SecretKeyFactory skf = getHkdfSecretKeyFactory("HmacSHA1");
    final SecretKeySpec sks = new SecretKeySpec(new byte[16], "AES");
    assertThrows(
        UnsupportedOperationException.class, () -> skf.getKeySpec(sks, SecretKeySpec.class));
    assertThrows(UnsupportedOperationException.class, () -> skf.translateKey(sks));
  }
}
