// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class KeyPairGeneratorTest {

  KeyPairGenerator getKeyPairGenerator(String alg) {
    try {
      return KeyPairGenerator.getInstance(alg, TestUtil.NATIVE_PROVIDER);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void testGenerateXECKeys() {
    TestUtil.assumeMinimumJavaVersion(17);
    final KeyPairGenerator keyPairGenerator = getKeyPairGenerator("X25519");
    assertEquals("X25519", keyPairGenerator.getAlgorithm());

    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    assertNotNull(keyPair);

    final PrivateKey privateKey = keyPair.getPrivate();
    assertNotNull(privateKey);
    assertEquals("PKCS#8", privateKey.getFormat());
    assertEquals("XDH", privateKey.getAlgorithm());
    assertEquals(48, privateKey.getEncoded().length);

    final PublicKey publicKey = keyPair.getPublic();
    assertNotNull(publicKey);
    assertEquals("X.509", publicKey.getFormat());
    assertEquals("XDH", publicKey.getAlgorithm());
    assertEquals(44, publicKey.getEncoded().length);
  }

  // Regression test for P470070813: JSSE's TLS 1.3 x25519 handshake initializes the XDH
  // KeyPairGenerator with NamedParameterSpec.X25519. ACCP previously threw
  // UnsupportedOperationException from initialize(), causing the JCA to silently fail over to
  // SunEC.
  @Test
  public void initializeWithNamedParameterSpecX25519() throws InvalidAlgorithmParameterException {
    TestUtil.assumeMinimumJavaVersion(17);
    final KeyPairGenerator keyPairGenerator = getKeyPairGenerator("XDH");
    keyPairGenerator.initialize(TestUtil.namedParameterSpec("X25519"), new SecureRandom());
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();
    assertNotNull(keyPair);
    assertEquals("XDH", keyPair.getPrivate().getAlgorithm());
    assertEquals("XDH", keyPair.getPublic().getAlgorithm());
    assertEquals(48, keyPair.getPrivate().getEncoded().length);
    assertEquals(44, keyPair.getPublic().getEncoded().length);
  }

  // ACCP only supports X25519, so an XDH generator asked for another curve (e.g. X448) must reject
  // the spec so the JCA can fail over rather than silently emit an X25519 key.
  @Test
  public void initializeWithUnsupportedNamedParameterSpecThrows() {
    TestUtil.assumeMinimumJavaVersion(17);
    final KeyPairGenerator keyPairGenerator = getKeyPairGenerator("XDH");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyPairGenerator.initialize(TestUtil.namedParameterSpec("X448"), new SecureRandom()));
  }

  // A null spec is rejected (rather than NPE'ing or silently generating a key).
  @Test
  public void initializeWithNullParamsThrows() {
    TestUtil.assumeMinimumJavaVersion(17);
    final KeyPairGenerator keyPairGenerator = getKeyPairGenerator("XDH");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyPairGenerator.initialize((AlgorithmParameterSpec) null, new SecureRandom()));
  }

  // A non-NamedParameterSpec (e.g. ECGenParameterSpec) is rejected so the JCA can fail over.
  @Test
  public void initializeWithNonNamedParameterSpecThrows() {
    TestUtil.assumeMinimumJavaVersion(17);
    final KeyPairGenerator keyPairGenerator = getKeyPairGenerator("XDH");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom()));
  }

  @Test
  public void testInitKeyPairNoOp() {
    TestUtil.assumeMinimumJavaVersion(17);
    for (String alg : new String[] {"Ed25519", "X25519", "XDH"}) {
      final KeyPairGenerator keyPairGenerator = getKeyPairGenerator(alg);
      // 255 is Curve25519's key size in bits; ACCP ignores it (and the SecureRandom),
      // but the call must not throw. This mirrors BouncyCastle TLS's invocation.
      keyPairGenerator.initialize(255, new SecureRandom());
      keyPairGenerator.generateKeyPair();
    }
  }
}
