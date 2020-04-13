// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetInternalClass;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandomSpi;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.AesCtrDrbg;
import com.amazon.corretto.crypto.provider.HmacMD5Spi;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;

public class ServiceSelfTestMetaTest {
    AmazonCorrettoCryptoProvider accp;

    @Before
    public void setUp() throws Throwable {
        // We need RDRAND support for a lot of these tests to work properly
        Assume.assumeTrue("RDRAND is supported", AmazonCorrettoCryptoProvider.isRdRandSupported());

        // AACP instances cache the self-test status within each Service, so create a new instance to clear that cache.
        // This also makes sure the native library is loaded.
        accp = new AmazonCorrettoCryptoProvider();
    }

    @After
    public void reset() throws Throwable {
        sneakyInvoke(AmazonCorrettoCryptoProvider.INSTANCE, "resetAllSelfTests");
        // It is unclear if JUnit always properly releases references to classes and thus we may have memory leaks
        // if we do not properly null our references
        accp = null;
    }

    @Test
    public void whenSelfTestsFail_nothingIsVended_exceptDRBG() throws Throwable {
        Object selfTest = TestUtil.sneakyGetField(HmacMD5Spi.class, "SELF_TEST");

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

        assertEquals(AmazonCorrettoCryptoProvider.isRdRandSupported(), drbgWasUsable);
    }

    @Test
    public void whenDRBGSelfTestsFail_nothingIsVended() throws Throwable {
        Class<?> spi = sneakyGetInternalClass(AesCtrDrbg.class, "SPI");
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
    public void whenSelfTestRecurses_recursionIsSuppressed() throws Throwable {
        // Reference to a SelfTestSuite.SelfTest
        AtomicReference<Object> selfTestRef = new AtomicReference<>();

        Supplier<SelfTestResult> recursiveSupplier = () -> {
            try {
                SelfTestResult result = (SelfTestResult)sneakyInvoke(selfTestRef.get(), "runTest");

                assertEquals(SelfTestStatus.RECURSIVELY_INVOKED, result.getStatus());

                return new SelfTestResult(SelfTestStatus.PASSED);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        };

        Object selfTest = sneakyConstruct(
                "com.amazon.corretto.crypto.provider.SelfTestSuite$SelfTest",
                "test-recursion",
                recursiveSupplier
        );

        selfTestRef.set(selfTest);

        assertEquals(SelfTestStatus.PASSED, ((SelfTestResult)sneakyInvoke(selfTest, "runTest")).getStatus());
    }


    @Test
    public void whenMultipleThreadsTest_doesNotDeadlock() throws Throwable {
        // Two threads must execute the self-test simultaneously for either to complete.
        CyclicBarrier barrier = new CyclicBarrier(2);

        Supplier<SelfTestResult> recursiveSupplier = () -> {
            try {
                barrier.await();

                return new SelfTestResult(SelfTestStatus.PASSED);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        };

        Object selfTest = sneakyConstruct(
                "com.amazon.corretto.crypto.provider.SelfTestSuite$SelfTest",

                "test-threads",
                recursiveSupplier
        );

        new Thread(() -> {
            try {
                sneakyInvoke(selfTest, "runTest");
            } catch (Throwable t) {}
        }).start();

        assertEquals(SelfTestStatus.PASSED, ((SelfTestResult)sneakyInvoke(selfTest, "runTest")).getStatus());
    }
}
