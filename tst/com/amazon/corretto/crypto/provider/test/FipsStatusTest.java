// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.FipsStatusException;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
// NOTE: we need to take global r/w lock on TestUtil because FIPS self test breakages
//       are global and would affect other tests executed concurrently with this one.
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class FipsStatusTest {

  private static final AmazonCorrettoCryptoProvider provider =
      AmazonCorrettoCryptoProvider.INSTANCE;
  private static final String PWCT_BREAKAGE_ENV_VAR = "BORINGSSL_FIPS_BREAK_TEST";

  @Test
  public void givenAccpBuiltWithFips_whenAWS_LC_fips_failure_callback_expectException()
      throws Exception {
    if (provider.isFips() && provider.isFipsSelfTestFailureSkipAbort()) {
      assertTrue(provider.isFipsStatusOk());
      assertEquals(0, provider.getFipsSelfTestFailures().size());
      assertNotNull(KeyGenerator.getInstance("AES", provider));
      // call the failure callback
      NativeTestHooks.callAwsLcFipsFailureCallback();
      assertFalse(provider.isFipsStatusOk());
      assertEquals(1, provider.getFipsSelfTestFailures().size());
      assertEquals("called by a test", provider.getFipsSelfTestFailures().get(0));
      // we should not be able to get any service object
      assertThrows(FipsStatusException.class, () -> KeyGenerator.getInstance("AES", provider));
      // we need to flip the status back to OK so the rest of tests would work. In practice, once
      // the flag is set to false, it remains false.
      NativeTestHooks.resetFipsStatus();
      assertTrue(provider.isFipsStatusOk());
    } else {
      assertThrows(UnsupportedOperationException.class, () -> provider.isFipsStatusOk());
      assertThrows(UnsupportedOperationException.class, () -> provider.getFipsSelfTestFailures());
    }
  }

  // Key generation should ~never fail under normal conditions, so consider a breakage to
  // indicate that AWS-LC was built with the FIPS_BREAK_TEST build flag set.
  private static boolean awsLcIsBuiltWitFipshBreakTest() throws Exception {
    final String algorithm = "RSA";
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
    TestUtil.setEnv(PWCT_BREAKAGE_ENV_VAR, String.format("%s_PWCT", algorithm));
    try {
      kpg.generateKeyPair();
    } catch (RuntimeCryptoException e) {
      return true;
    } finally {
      TestUtil.setEnv(PWCT_BREAKAGE_ENV_VAR, null);
    }
    return false;
  }

  private static void testPwctBreakage(final String algo, String envVarValue) throws Exception {
    NativeTestHooks.resetFipsStatus();
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo, provider);
    assertTrue(provider.isFipsStatusOk());
    // Set PWCT_BREAKAGE_ENV_VAR for desired keygen test to break it
    TestUtil.setEnv(PWCT_BREAKAGE_ENV_VAR, envVarValue);
    // Key generation should now fail
    assertThrows(RuntimeCryptoException.class, () -> kpg.generateKeyPair());
    // Global FIPS status should not be OK, and we shouldn't be able to get more KPG instances
    assertTrue(provider.getFipsSelfTestFailures().size() > 0);
    assertFalse(provider.isFipsStatusOk());
    assertThrows(FipsStatusException.class, () -> KeyPairGenerator.getInstance(algo, provider));
    // Self-test error messages should reference the expected algorithm
    for (String msg : provider.getFipsSelfTestFailures()) {
      assertTrue(msg.contains(algo));
    }
    // Be sure to reset provider-global state!
    TestUtil.setEnv(PWCT_BREAKAGE_ENV_VAR, null);
    assertNotNull(kpg.generateKeyPair());
    NativeTestHooks.resetFipsStatus();
    assertTrue(provider.isFipsStatusOk());
  }

  @Test
  public void testPwctBreakageSkipAbort() throws Exception {
    assumeTrue(provider.isFips());
    assumeTrue(provider.isFipsSelfTestFailureSkipAbort());
    assumeTrue(awsLcIsBuiltWitFipshBreakTest());
    testPwctBreakage("RSA", "RSA_PWCT");
    testPwctBreakage("EC", "EC_PWCT");
    testPwctBreakage("Ed25519", "EDDSA_PWCT");
    if (provider.isExperimentalFips()) { // can be removed when AWS-LC-FIPS supports ML-DSA
      testPwctBreakage("ML-DSA", "MLDSA_PWCT");
    }
  }
}
