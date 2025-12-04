// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.utils.EcUtils;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EcUtilsTest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

  @Test
  public void testEcPrivateKeyEncodingDifferences() throws Exception {
    KeyPairGenerator accpKpg = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    accpKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair accpKeyPair = accpKpg.generateKeyPair();
    PrivateKey accpPrivateKey = accpKeyPair.getPrivate();

    // Convert ACCP private key via BouncyCastle KeyFactory
    KeyFactory bcKf = KeyFactory.getInstance("EC", TestUtil.BC_PROVIDER);
    PrivateKey bcPrivateKey =
        bcKf.generatePrivate(new PKCS8EncodedKeySpec(accpPrivateKey.getEncoded()));

    // Assert that the ACCP key does not match BouncyCastle's encoding of the
    // same key, and that BC's key is in fact larger due to redundant OID.
    TestUtil.assertArraysHexNotEquals(bcPrivateKey.getEncoded(), accpPrivateKey.getEncoded());
    assertTrue(bcPrivateKey.getEncoded().length > accpPrivateKey.getEncoded().length);

    // Assert that ACCP's RFC 5915 encoded key matches BouncyCastle
    byte[] rfc5915AccpKey = EcUtils.encodeRfc5915EcPrivateKey(accpPrivateKey);
    TestUtil.assertArraysHexEquals(bcPrivateKey.getEncoded(), rfc5915AccpKey);
  }

  @Test
  public void testBothProvidersCanParseAccpVanillaFormat() throws Exception {
    // Generate EC key pair with ACCP
    KeyPairGenerator accpKpg = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    accpKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair accpKeyPair = accpKpg.generateKeyPair();
    PrivateKey accpPrivateKey = accpKeyPair.getPrivate();

    // Get the non-RFC-59515 ACCP (vanilla) format
    byte[] vanillaAccpKey = accpPrivateKey.getEncoded();

    // Test that both ACCP and BouncyCastle can parse the vanilla format
    KeyFactory accpKf = KeyFactory.getInstance("EC", NATIVE_PROVIDER);
    PrivateKey accpParsed = accpKf.generatePrivate(new PKCS8EncodedKeySpec(vanillaAccpKey));
    assertNotNull(accpParsed, "ACCP should be able to parse vanilla format");

    KeyFactory bcKf = KeyFactory.getInstance("EC", TestUtil.BC_PROVIDER);
    PrivateKey bcParsed = bcKf.generatePrivate(new PKCS8EncodedKeySpec(vanillaAccpKey));
    assertNotNull(bcParsed, "BouncyCastle should be able to parse vanilla format");
  }

  @Test
  public void testAccpCanParseRfc5915Format() throws Exception {
    // Generate EC key pair with BC in RFC 59515 format (BC's default)
    KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", TestUtil.BC_PROVIDER);
    bcKpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair bcKeyPair = bcKpg.generateKeyPair();
    PrivateKey bcPrivateKey = bcKeyPair.getPrivate();

    // Test that ACCP can parse BC's RFC 5915 format
    KeyFactory accpKf = KeyFactory.getInstance("EC", NATIVE_PROVIDER);
    PrivateKey accpParsed =
        accpKf.generatePrivate(new PKCS8EncodedKeySpec(bcPrivateKey.getEncoded()));
    assertNotNull(accpParsed, "Should be able to parse BC RFC 5915 format");
  }

  @Test
  public void testKeyLengthDifferences() throws Exception {
    // Generate EC key pair with ACCP
    KeyPairGenerator accpKpg = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    accpKpg.initialize(new ECGenParameterSpec("secp256r1"));
    PrivateKey accpKey = accpKpg.generateKeyPair().getPrivate();

    // Get original ACCP key length
    int originalLength = accpKey.getEncoded().length;

    // Encode the ACCP key in RFC 5915 format and verify it has a different length
    byte[] rfc5915AccpKey = EcUtils.encodeRfc5915EcPrivateKey(accpKey);
    int rfc5915Length = rfc5915AccpKey.length;

    // Assert that RFC 5915 key is longer than original
    assertNotEquals(
        originalLength,
        rfc5915Length,
        "RFC 5915 ACCP key should have different length than original");

    // Generate a BouncyCastle key for comparison
    KeyPairGenerator bcKpg = KeyPairGenerator.getInstance("EC", TestUtil.BC_PROVIDER);
    bcKpg.initialize(new ECGenParameterSpec("secp256r1"));
    PrivateKey bcKey = bcKpg.generateKeyPair().getPrivate();

    // Verify RFC 5915 ACCP key has same length as BouncyCastle key
    assertEquals(
        bcKey.getEncoded().length,
        rfc5915Length,
        "RFC 5915 ACCP key should have same length as BouncyCastle key");
  }
}
