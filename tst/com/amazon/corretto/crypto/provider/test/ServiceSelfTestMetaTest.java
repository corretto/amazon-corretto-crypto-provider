// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER_PACKAGE;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetInternalClass;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.SelfTestFailureException;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class ServiceSelfTestMetaTest {
  AmazonCorrettoCryptoProvider accp;

  @BeforeEach
  public void setUp() throws Throwable {
    // ACCP instances cache the self-test status within each Service, so create a new instance to
    // clear that cache.
    // This also makes sure the native library is loaded.
    accp = new AmazonCorrettoCryptoProvider();
  }

  @AfterEach
  public void reset() throws Throwable {
    sneakyInvoke(AmazonCorrettoCryptoProvider.INSTANCE, "resetAllSelfTests");
    // It is unclear if JUnit always properly releases references to classes and thus we may have
    // memory leaks
    // if we do not properly null our references
    accp = null;
  }

  @Test
  public void whenSelfTestsFail_nothingIsVended_exceptDRBG() throws Throwable {
    Class<?> spiClass = Class.forName(NATIVE_PROVIDER_PACKAGE + ".EvpHmac$SHA256");
    Object selfTest = TestUtil.sneakyGetField(spiClass, "SELF_TEST");

    sneakyInvoke(selfTest, "forceFailure");

    boolean drbgWasUsable = false;

    for (Provider.Service service : accp.getServices()) {
      try {
        Object instance = service.newInstance(null);

        // The DRBG ignores other algorithm self-tests to avoid recursive initialization issues
        assertTrue(instance instanceof SecureRandomSpi);

        drbgWasUsable = true;
      } catch (NoSuchAlgorithmException e) {
        // ok - expected
      }
    }

    // Check to see if we can get an instance of SecureRandom
    SecureRandom.getInstance("DEFAULT", accp);
  }

  @Test
  public void whenDRBGSelfTestsFail_nothingIsVended() throws Throwable {
    Class<?> spi =
        sneakyGetInternalClass(
            Class.forName("com.amazon.corretto.crypto.provider.LibCryptoRng"), "SPI");
    Object test = TestUtil.sneakyGetField(spi, "SELF_TEST");
    sneakyInvoke(test, "forceFailure");

    for (Provider.Service service : accp.getServices()) {
      try {
        Object instance = service.newInstance(null);

        fail("Got unexpected service instance: " + instance);
      } catch (NoSuchAlgorithmException e) {
        // ok - expected
      }
    }
  }

  @Test
  public void whenAwsLcSelfTestsFail_assertHealthyThrowsException() throws Throwable {
    forceFailAwsLcSelfTests();
    assertSame(SelfTestStatus.FAILED, AmazonCorrettoCryptoProvider.INSTANCE.getSelfTestStatus());
    assertThrows(
        SelfTestFailureException.class,
        () -> AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy());
  }

  private static void forceFailAwsLcSelfTests() throws Exception {
    final Class<?> selfTestSuiteClz =
        Class.forName("com.amazon.corretto.crypto.provider.SelfTestSuite");
    final Field test = selfTestSuiteClz.getDeclaredField("AWS_LC_SELF_TESTS");
    test.setAccessible(true);
    final Object obj = test.get(null);
    final Class<?> selfTestClz = obj.getClass();
    final Method m = selfTestClz.getDeclaredMethod("forceFailure");
    m.setAccessible(true);
    m.invoke(obj);
  }

  @Test
  public void whenSelfTestRecurses_recursionIsSuppressed() throws Throwable {
    // Reference to a SelfTestSuite.SelfTest
    AtomicReference<Object> selfTestRef = new AtomicReference<>();

    Supplier<SelfTestResult> recursiveSupplier =
        () -> {
          try {
            SelfTestResult result = sneakyInvoke(selfTestRef.get(), "runTest");

            assertEquals(SelfTestStatus.RECURSIVELY_INVOKED, result.getStatus());

            return new SelfTestResult(SelfTestStatus.PASSED);
          } catch (Throwable t) {
            throw new RuntimeException(t);
          }
        };

    Object selfTest =
        sneakyConstruct(
            "com.amazon.corretto.crypto.provider.SelfTestSuite$SelfTest",
            "test-recursion",
            recursiveSupplier);

    selfTestRef.set(selfTest);

    assertEquals(
        SelfTestStatus.PASSED, ((SelfTestResult) sneakyInvoke(selfTest, "runTest")).getStatus());
  }

  @Test
  public void whenMultipleThreadsTest_doesNotDeadlock() throws Throwable {
    // Two threads must execute the self-test simultaneously for either to complete.
    CyclicBarrier barrier = new CyclicBarrier(2);

    Supplier<SelfTestResult> recursiveSupplier =
        () -> {
          try {
            barrier.await();

            return new SelfTestResult(SelfTestStatus.PASSED);
          } catch (Throwable t) {
            throw new RuntimeException(t);
          }
        };

    Object selfTest =
        sneakyConstruct(
            "com.amazon.corretto.crypto.provider.SelfTestSuite$SelfTest",
            "test-threads",
            recursiveSupplier);

    new Thread(
            () -> {
              try {
                sneakyInvoke(selfTest, "runTest");
              } catch (Throwable t) {
              }
            })
        .start();

    assertEquals(
        SelfTestStatus.PASSED, ((SelfTestResult) sneakyInvoke(selfTest, "runTest")).getStatus());
  }

  @Test
  public void givenACCPCacheSelfTestResultsPropertySetToFalse_whenRunTests_ExpectReset()
      throws Throwable {
    reset();
    System.setProperty("com.amazon.corretto.crypto.provider.cacheselftestresults", "false");
    accp = new AmazonCorrettoCryptoProvider();
    assertNotSame(SelfTestStatus.FAILED, accp.runSelfTests());
    // Let's force a failure and re run the tests
    Class<?> spiClass = Class.forName(NATIVE_PROVIDER_PACKAGE + ".EvpHmac$SHA256");
    Object selfTest = TestUtil.sneakyGetField(spiClass, "SELF_TEST");
    sneakyInvoke(selfTest, "forceFailure");
    assertSame(SelfTestStatus.FAILED, accp.getSelfTestStatus());
    // re-run the tests and confirm that they don't fail anymore
    assertNotSame(SelfTestStatus.FAILED, accp.runSelfTests());
    assertNotSame(SelfTestStatus.FAILED, accp.getSelfTestStatus());
  }
}
