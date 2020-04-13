// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.function.Supplier;
import java.util.logging.Logger;

class SelfTestSuite {
    private static final Logger LOGGER = Logger.getLogger(SelfTestSuite.class.getName());

    static class SelfTest {
        private static final AtomicReferenceFieldUpdater<SelfTest, SelfTestResult>
            update_result = AtomicReferenceFieldUpdater.newUpdater(SelfTest.class, SelfTestResult.class, "result");

        private final String algorithmName;
        private final Supplier<SelfTestResult> selfTestRunner;
        private volatile SelfTestResult result;

        // Recursive invocation of self-tests can result in all kinds of problems; unfortunately due to how the JCE's
        // internal provider-verification systems in turn depend on the loaded JCE providers, this can be unavoidable.
        // To try to mitigate it, we'll refuse to invoke any particular self test recursively, and treat the algorithm
        // as unusable until we unwind the stack and complete the self-test.
        //
        // Note that a lock for this isn't the right way to go - we need to avoid deadlocks due to class static
        // initializers and the classloader lock. So instead we'll run redundant self-tests if we race multiple threads.
        //
        // Finally, this is a per-SelfTest map because we need to recursively invoke the DRBG self-tests during
        // JceSecurity static initialization (triggered by other self-tests) in some cases.
        private ConcurrentHashMap<Thread, Object> activeThreads = new ConcurrentHashMap<>();

        public SelfTest(String algorithmName, Supplier<SelfTestResult> selfTestRunner) {
            this.algorithmName = algorithmName;
            this.selfTestRunner = selfTestRunner;
            resetStatus();
        }

        public String getAlgorithmName() {
            return algorithmName;
        }

        public SelfTestResult runTest() {
            SelfTestResult currentResult = result;
            if (currentResult.getStatus() != SelfTestStatus.NOT_RUN) {
                return currentResult;
            }

            if (activeThreads.putIfAbsent(Thread.currentThread(), true) != null) {
                return new SelfTestResult(SelfTestStatus.RECURSIVELY_INVOKED);
            }

            try {
                SelfTestResult localResult = runTest0();

                return update_result.updateAndGet(this, oldResult -> oldResult.combine(localResult));
            } finally {
                activeThreads.remove(Thread.currentThread());
            }
        }

        private SelfTestResult runTest0() {
            SelfTestResult localResult = selfTestRunner.get();

            if (localResult.getStatus() == SelfTestStatus.PASSED) {
                LOGGER.finer(() -> String.format("Self-test result for JCE algo %s: PASSED",
                                                 getAlgorithmName()));
            } else {
                LOGGER.severe(
                        () -> {
                            StringWriter sw = new StringWriter();

                            sw.append(String.format("Self-test result for JCE algo %s: %s",
                                                    getAlgorithmName(), localResult.getStatus()));

                            if (localResult.getThrowable() != null) {
                                sw.append("\n");
                                localResult.getThrowable().printStackTrace(new PrintWriter(sw));
                            }

                            return sw.toString();
                        }
                );
            }

            return localResult;
        }

        public SelfTestResult getCachedResult() {
            return result;
        }

        public void assertSelfTestPassed() throws SelfTestFailureException {
            if (!SelfTestStatus.PASSED.equals(runTest().getStatus())) {
                throw new SelfTestFailureException("Self-test for " + getAlgorithmName() + " failed: " + result, result.getThrowable());
            }
        }

        // For testing
        private void resetStatus() {
            this.result = new SelfTestResult(SelfTestStatus.NOT_RUN);
        }

        @SuppressWarnings("unused") // invoked reflectively
        private void forceFailure() {
            this.result = new SelfTestResult(new RuntimeException("Forced failure"));
        }
    }

    private ConcurrentHashMap<String, SelfTest> selfTests = new ConcurrentHashMap<>();

    void addSelfTest(SelfTest test) {
        if (selfTests.putIfAbsent(test.getAlgorithmName(), test) != null) {
            throw new IllegalArgumentException("Duplicate test for algorithm " + test.getAlgorithmName());
        }
    }

    public void resetAllSelfTests() {
        selfTests.values().forEach(SelfTest::resetStatus);
    }

    public SelfTestStatus getOverallStatus() {
        if (selfTests.isEmpty()) {
            throw new IllegalStateException("No self-tests added");
        }

        SelfTestStatus result = SelfTestStatus.PASSED;

        for (SelfTest singleTest : selfTests.values()) {
            result = result.combineMultipleTests(singleTest.getCachedResult().getStatus());
        }

        return result;
    }

    public Map<String, SelfTestResult> getAllTestResults() {
        HashMap<String, SelfTestResult> results = new HashMap<>(selfTests.size());

        selfTests.forEach(
                (k, v) -> results.put(k, v.getCachedResult())
        );

        return results;
    }

    public void assertAllTestsPassed() throws SelfTestFailureException {
        if (!runTests().equals(SelfTestStatus.PASSED)) {
            final Map<String, SelfTestResult> results = getAllTestResults();
            final SelfTestFailureException ex = new SelfTestFailureException("Failed self-tests");

            for (final Map.Entry<String, SelfTestResult> entry : results.entrySet()) {
                final SelfTestResult result = entry.getValue();

                if (!result.getStatus().equals(SelfTestStatus.PASSED)) {
                    ex.addSuppressed(new SelfTestFailureException(
                            "Self-test for " + entry.getKey() + " failed: " + result,
                            result.getThrowable()));
                }
            }
            throw ex;
        }
    }

    public SelfTestStatus runTests() {
        selfTests.forEach(
                (algoName, test) -> test.runTest()
        );

        return getOverallStatus();
    }
}
