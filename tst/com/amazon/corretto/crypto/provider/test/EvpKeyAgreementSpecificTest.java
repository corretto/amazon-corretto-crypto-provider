// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetField;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvokeExplicit;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

/** This class contains non-parameterized tests to cover specific cases. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EvpKeyAgreementSpecificTest {
  private static final Class<?> SPI_CLASS;
  private static final KeyPair EC_KEYPAIR;

  static {
    try {
      SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.EvpKeyAgreement");

      // Force loading of native library
      KeyAgreement.getInstance("ECDH", NATIVE_PROVIDER);

      KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
      gen.initialize(new ECGenParameterSpec("NIST P-256"));
      EC_KEYPAIR = gen.generateKeyPair();
    } catch (final Exception ex) {
      throw new AssertionError(ex);
    }
  }

  @Test
  public void wrongKeyTypes() throws Exception {
    final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    final KeyPair rsaPair = gen.generateKeyPair();
    assertThrows(
        InvalidKeyException.class, () -> agree(EC_KEYPAIR.getPrivate(), rsaPair.getPublic()));

    assertThrows(
        InvalidKeyException.class, () -> agree(rsaPair.getPrivate(), EC_KEYPAIR.getPublic()));
  }

  @Test
  public void paramMismatch() {
    assertThrows(
        InvalidKeyException.class,
        () ->
            agree(
                EC_KEYPAIR.getPrivate(),
                EvpKeyAgreementTest.buildKeyOnWrongCurve((ECPublicKey) EC_KEYPAIR.getPublic())));
  }

  @Test
  public void evilEcKeys() {
    final Key privKey = EC_KEYPAIR.getPrivate();
    assertThrows(
        InvalidKeyException.class,
        () ->
            agree(
                privKey,
                EvpKeyAgreementTest.buildKeyAtInfinity((ECPublicKey) EC_KEYPAIR.getPublic())));

    assertThrows(
        InvalidKeyException.class,
        () ->
            agree(
                privKey,
                EvpKeyAgreementTest.buildKeyOffCurve((ECPublicKey) EC_KEYPAIR.getPublic())));
  }

  private static void assertKeyEquals(String message, Key a, Key b) {
    assertEquals(a.getFormat(), b.getFormat(), message);
    assertArrayEquals(a.getEncoded(), b.getEncoded(), message);
  }

  private static byte[] agree(Key privateKeyRaw, Key publicKeyRaw) throws Throwable {
    KeyFactory kf = KeyFactory.getInstance("EC", NATIVE_PROVIDER);

    Key privateKey = kf.translateKey(privateKeyRaw);
    Key publicKey = kf.translateKey(publicKeyRaw);

    // Horribly evil!
    synchronized (privateKey) {
      synchronized (publicKey) {
        long privatePtr =
            (long)
                sneakyGetField(
                    sneakyGetField(sneakyGetField(privateKey, "internalKey"), "cell"), "ptr");
        long publicPtr =
            (long)
                sneakyGetField(
                    sneakyGetField(sneakyGetField(publicKey, "internalKey"), "cell"), "ptr");
        return sneakyInvokeExplicit(SPI_CLASS, "agree", null, privatePtr, publicPtr);
      }
    }
  }
}
