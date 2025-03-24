// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.restoreProviders;
import static com.amazon.corretto.crypto.provider.test.TestUtil.saveProviders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

/** Contains miscellaneous tests which must be run in a single-threaded environment. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
@ResourceLock(value = TestUtil.RESOURCE_PROVIDER, mode = ResourceAccessMode.READ_WRITE)
public class MiscSingleThreadedTests {

  @AfterAll
  public static void cleanup() {
    Security.removeProvider(NATIVE_PROVIDER.getName());
    for (Provider provider : Security.getProviders()) {
      assertFalse(NATIVE_PROVIDER.equals(provider.getName()));
    }
  }

  /**
   * We do not (currently) support the signature NONEwithRSA, but the JCE implements it internally
   * with Cipher.getInstance("RSA/ECB/PKCS1Padding"), which we do support. In certain cases we can
   * cause this to fail. It does require that the provider ordering be relatively specific and that
   * we call .getProvider() on the Signature objects prior to initializing them.
   */
  @Test
  public void testNoneWithRsa() throws Exception {
    assumeMinimumVersion("1.0.1", AmazonCorrettoCryptoProvider.INSTANCE);

    final Provider[] oldProviders = saveProviders();
    try {
      AmazonCorrettoCryptoProvider.install();
      final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
      kg.initialize(2048);
      final KeyPair pair = kg.generateKeyPair();

      final Signature signer = Signature.getInstance("NONEwithRSA");
      signer.getProvider();
      signer.initSign(pair.getPrivate());
      signer.update("TestData".getBytes(StandardCharsets.UTF_8));
      final byte[] signature = signer.sign();

      final Signature verifier = Signature.getInstance("NONEwithRSA");
      verifier.getProvider();
      verifier.initVerify(pair.getPublic());
      verifier.update("TestData".getBytes(StandardCharsets.UTF_8));
      assertTrue(verifier.verify(signature));
    } finally {
      restoreProviders(oldProviders);
    }
  }

  /** We should not be register any cipher with the alias "AES", defer to SunJCE for that alias. */
  @Test
  public void testNoAESCipherRegistered() throws Exception {
    final Provider[] oldProviders = saveProviders();
    try {
      AmazonCorrettoCryptoProvider.install();
      assertNotEquals(
          ((Provider) TestUtil.NATIVE_PROVIDER).getName(),
          Cipher.getInstance("AES").getProvider().getName());
    } finally {
      restoreProviders(oldProviders);
    }
  }

  /**
   * Test to ensure FIPS mode works correctly.
   *
   * <p>While this test doesn't need to be run in a single-threaded environment, there is no other
   * good "catch-all" place for this test to land.
   */
  @Test
  public void correctFipsMode() {
    final boolean fipsMode = Boolean.getBoolean("FIPS");
    assertEquals(fipsMode, NATIVE_PROVIDER.isFips());
  }
}
