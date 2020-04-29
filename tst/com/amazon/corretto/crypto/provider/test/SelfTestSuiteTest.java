// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.argsCompatible;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import com.amazon.corretto.crypto.provider.SelfTestFailureException;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@SuppressWarnings("rawtypes")
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class SelfTestSuiteTest {
    /* SelfTestSuite is not a public API, so we don't want to make it public. However, we can't put this test in the
     * same package, because if we do and try to run the test with a signed JAR, the tests will fail due to a signer
     * information mismatch error. So we'll use reflection to get access :/
     */
    private static final Class<?> CLASS_SELF_TEST_SUITE, CLASS_SELF_TEST, CLASS_RESULT, CLASS_STATUS;
    // SelfTestStatus enum constants
    private static final Object PASSED, NOT_RUN, FAILED;

    static {
        try {
            ClassLoader loader = SelfTestSuiteTest.class.getClassLoader();
            CLASS_SELF_TEST_SUITE = loader.loadClass("com.amazon.corretto.crypto.provider.SelfTestSuite");
            CLASS_SELF_TEST = loader.loadClass("com.amazon.corretto.crypto.provider.SelfTestSuite$SelfTest");
            CLASS_RESULT = loader.loadClass("com.amazon.corretto.crypto.provider.SelfTestResult");
            CLASS_STATUS = loader.loadClass("com.amazon.corretto.crypto.provider.SelfTestStatus");

            PASSED = getStaticField(CLASS_STATUS, "PASSED");
            FAILED = getStaticField(CLASS_STATUS, "FAILED");
            NOT_RUN = getStaticField(CLASS_STATUS, "NOT_RUN");
        } catch (Exception e) {
            throw rethrow(e);
        }
    }

    private static Object getStaticField(final Class<?> klass, final String name) {
        try {
            Field field = klass.getDeclaredField(name);
            field.setAccessible(true);

            return field.get(null);
        } catch (Exception e) {
            throw rethrow(e);
        }
    }

    private static Object newInstance(final Class<?> klass, final Object... args) {
        try {
            for (Constructor<?> ctor : klass.getDeclaredConstructors()) {
                if (argsCompatible(ctor.getParameterTypes(), args)) {
                    ctor.setAccessible(true);
                    return ctor.newInstance(args);
                }
            }

            throw new RuntimeException("No matching ctor");
        } catch (InvocationTargetException e) {
            throw rethrow(e.getCause());
        } catch (Exception e) {
            throw rethrow(e);
        }
    }

    @Test
    public void testCombinations() {
        SelfTestResult notRun = new SelfTestResult(SelfTestStatus.NOT_RUN);
        SelfTestResult recursing = new SelfTestResult(SelfTestStatus.RECURSIVELY_INVOKED);
        SelfTestResult passed = new SelfTestResult(SelfTestStatus.PASSED);
        SelfTestResult failed = new SelfTestResult(new Exception());

        assertEquals(notRun, notRun.combine(notRun));
        assertEquals(recursing, notRun.combine(recursing));
        assertEquals(passed, notRun.combine(passed));
        assertEquals(failed, notRun.combine(failed));

        assertEquals(recursing, recursing.combine(notRun));
        assertEquals(recursing, recursing.combine(recursing));
        assertEquals(passed, recursing.combine(passed));
        assertEquals(failed, recursing.combine(failed));

        assertEquals(passed, passed.combine(notRun));
        assertEquals(passed, passed.combine(recursing));
        assertEquals(passed, passed.combine(passed));
        assertEquals(failed, passed.combine(failed));

        assertEquals(failed, failed.combine(notRun));
        assertEquals(failed, failed.combine(recursing));
        assertEquals(failed, failed.combine(passed));
        assertEquals(failed, failed.combine(failed));
    }

    @Test
    public void whenAllTestsPass_suiteResultIsPass() throws Throwable {
        Object suite = newInstance(CLASS_SELF_TEST_SUITE);

        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
               );
        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 2", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
        );

        assertEquals(NOT_RUN, sneakyInvoke(suite, "getOverallStatus"));
        assertEquals(PASSED, sneakyInvoke(suite, "runTests"));
        assertEquals(PASSED, sneakyInvoke(suite, "getOverallStatus"));

        Map allTestResults = (Map)sneakyInvoke(suite, "getAllTestResults");
        assertEquals(PASSED, sneakyInvoke(allTestResults.get("ALGO 1"), "getStatus"));
        assertEquals(PASSED, sneakyInvoke(allTestResults.get("ALGO 2"), "getStatus"));
        sneakyInvoke(suite, "assertAllTestsPassed");
    }

    @Test
    public void whenOneTestFails_suiteResultIsFailed() throws Throwable {
        Object suite = newInstance(CLASS_SELF_TEST_SUITE);

        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
        );
        Object failingTest = newInstance(CLASS_SELF_TEST, "ALGO 2",
                               (Supplier) () -> newInstance(CLASS_RESULT, new RuntimeException()));
        sneakyInvoke(suite, "addSelfTest", failingTest);

        assertEquals(NOT_RUN, sneakyInvoke(suite, "getOverallStatus"));
        assertEquals(FAILED, sneakyInvoke(suite, "runTests"));
        assertEquals(FAILED, sneakyInvoke(suite, "getOverallStatus"));

        Map allTestResults = (Map)sneakyInvoke(suite, "getAllTestResults");
        assertEquals(PASSED, sneakyInvoke(allTestResults.get("ALGO 1"), "getStatus"));
        assertEquals(FAILED, sneakyInvoke(allTestResults.get("ALGO 2"), "getStatus"));

        try {
            sneakyInvoke(failingTest, "assertSelfTestPassed");
            fail();
        } catch (SelfTestFailureException e) {
            // ok
        }

        try {
            sneakyInvoke(suite, "assertAllTestsPassed");
            fail();
        } catch (SelfTestFailureException e) {
            // Should suppress exactly one SelfTestFailure exception
            final Throwable[] suppressed = e.getSuppressed();
            assertEquals(1, suppressed.length);
            assertTrue(suppressed[0] instanceof SelfTestFailureException);
        }
    }

    @Test
    public void whenMultipleTestsFail_suiteResultIsFailed() throws Throwable {
        Object suite = newInstance(CLASS_SELF_TEST_SUITE);

        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
        );
        Object failingTest1 = newInstance(CLASS_SELF_TEST, "ALGO 2",
                               (Supplier) () -> newInstance(CLASS_RESULT, new RuntimeException()));
        sneakyInvoke(suite, "addSelfTest", failingTest1);
        Object failingTest2 = newInstance(CLASS_SELF_TEST, "ALGO 3",
                (Supplier) () -> newInstance(CLASS_RESULT, new RuntimeException()));
        sneakyInvoke(suite, "addSelfTest", failingTest2);

        assertEquals(NOT_RUN, sneakyInvoke(suite, "getOverallStatus"));
        assertEquals(FAILED, sneakyInvoke(suite, "runTests"));
        assertEquals(FAILED, sneakyInvoke(suite, "getOverallStatus"));

        Map allTestResults = (Map)sneakyInvoke(suite, "getAllTestResults");
        assertEquals(PASSED, sneakyInvoke(allTestResults.get("ALGO 1"), "getStatus"));
        assertEquals(FAILED, sneakyInvoke(allTestResults.get("ALGO 2"), "getStatus"));

        try {
            sneakyInvoke(failingTest1, "assertSelfTestPassed");
            fail();
        } catch (SelfTestFailureException e) {
            // ok
        }
        try {
            sneakyInvoke(failingTest2, "assertSelfTestPassed");
            fail();
        } catch (SelfTestFailureException e) {
            // ok
        }

        try {
            sneakyInvoke(suite, "assertAllTestsPassed");
            fail();
        } catch (SelfTestFailureException e) {
            // Should suppress exactly one SelfTestFailure exception
            final Throwable[] suppressed = e.getSuppressed();
            assertEquals(2, suppressed.length);
            assertTrue(suppressed[0] instanceof SelfTestFailureException);
            assertTrue(suppressed[1] instanceof SelfTestFailureException);
        }
    }

    @Test
    public void whenRunTestsInvokedMultipleTimes_testsPerformedOnce() throws Throwable {
        AtomicInteger testRunCounter = new AtomicInteger(0);

        Object suite = newInstance(CLASS_SELF_TEST_SUITE);
        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1",
                           (Supplier)() -> {
                               testRunCounter.incrementAndGet();
                               return newInstance(CLASS_RESULT, PASSED);
                           })
        );

        assertEquals(PASSED, sneakyInvoke(suite, "runTests"));
        assertEquals(PASSED, sneakyInvoke(suite, "runTests"));

        assertEquals(1, testRunCounter.get());
    }

    @Test
    public void whenDuplicateTestsPresent_addSelfTestFails() throws Throwable {
        Object suite = newInstance(CLASS_SELF_TEST_SUITE);

        sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
        );
        assertThrows(IllegalArgumentException.class, () ->
            sneakyInvoke(suite, "addSelfTest",
               newInstance(CLASS_SELF_TEST, "ALGO 1", (Supplier)() -> newInstance(CLASS_RESULT, PASSED))
            ));
    }

    @Test
    public void whenNoTestsPresent_testRunThrows() throws Throwable {
        Object suite = newInstance(CLASS_SELF_TEST_SUITE);

        assertThrows(IllegalStateException.class, () -> sneakyInvoke(suite, "runTests"));
    }

    @Test
    public void whenThreadsRace_noDeadlockOccurs() throws Throwable {
        CyclicBarrier barrier = new CyclicBarrier(2);

        Supplier testSupplier = () -> {
            try {
                barrier.await();
                return newInstance(CLASS_RESULT, PASSED);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        Object suite = newInstance(CLASS_SELF_TEST_SUITE);
        sneakyInvoke(suite, "addSelfTest",
                     newInstance(CLASS_SELF_TEST, "ALGO 1", testSupplier)
        );

        Thread thread = new Thread(() -> {
            try {
                sneakyInvoke(suite, "runTests");
            } catch (Throwable t) {}
        });

        thread.start();
        sneakyInvoke(suite, "runTests");
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException) {
            throw (RuntimeException)t;
        } else if (t instanceof Error) {
            throw (Error)t;
        } else {
            return new RuntimeException(t);
        }
    }
}

