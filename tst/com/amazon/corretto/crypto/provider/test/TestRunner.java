// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.experimental.ParallelComputer;
import org.junit.internal.builders.AllDefaultPossibilitiesBuilder;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;
import org.junit.runner.Runner;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;
import org.junit.runners.model.InitializationError;

import com.amazon.corretto.crypto.provider.test.integration.ExternalHTTPSIntegrationTest;
import com.amazon.corretto.crypto.provider.test.integration.LocalHTTPSIntegrationTest;

@SuppressWarnings({"rawtypes", "deprecation"})
public class TestRunner {
    private static final String BRIGHT_TEXT = (char)27 + "[1m";
    private static final String BRIGHT_RED_TEXT = (char)27 + "[31;1m";
    private static final String BRIGHT_GREEN_TEXT = (char)27 + "[32;1m";
    private static final String BRIGHT_CYAN_TEXT = (char)27 + "[36;1m";
    private static final String NORMAL_TEXT = (char)27 + "[0m";
    private static final String NOT_YET_FAILED_NOTICE = "  ";
    private static final String ALREADY_FAILED_NOTICE = BRIGHT_RED_TEXT + "!" + NORMAL_TEXT;
    private static final String STARTED_NOTICE = BRIGHT_TEXT +                "[STARTED]         " + NORMAL_TEXT;
    private static final String PASSED_NOTICE = BRIGHT_GREEN_TEXT +           "[PASSED]          " + NORMAL_TEXT;
    private static final String ASSUMPTION_FAILED_NOTICE = BRIGHT_CYAN_TEXT + "[FALSE_ASSUMPTION]" + NORMAL_TEXT;
    private static final String FAILED_NOTICE = BRIGHT_RED_TEXT +             "[FAILED]          " + NORMAL_TEXT;
    private static final String IGNORED_NOTICE = BRIGHT_CYAN_TEXT +           "[IGNORED]         " + NORMAL_TEXT;

    private static final Map<String, Class[]> SUITES_PARALLEL;
    private static final Map<String, Class[]> SUITES_SERIAL;

    static {
        Map<String, Class[]> tmp = new HashMap<>();
        tmp.put("unit", new Class[] {
                AccessibleByteArrayOutputStreamTest.class,
                AesCtrDrbgTest.class,
                AESGenerativeTest.class,
                EcGenTest.class,
                EvpKeyAgreementTest.class,
                EvpKeyAgreementSpecificTest.class,
                EvpSignatureSpecificTest.class,
                EvpSignatureTest.class,
                HmacTest.class,
                RsaCipherTest.class,
                RsaGenTest.class,
                SelfTestSuiteTest.class,
                UtilsTest.class,
                InputBufferTest.class,
                NativeTest.class
                });
        SUITES_PARALLEL = Collections.unmodifiableMap(tmp);

        tmp = new HashMap<>();
        tmp.put("unit", new Class[] {
                MiscSingleThreadedTests.class,
                AesTest.class,     // Interacts with ReflectiveTools
                JanitorTest.class, // Already multi-threaded
                MD5Test.class,     // Interacts with ReflectiveTools
                SHA1Test.class,    // Interacts with ReflectiveTools
                SHA256Test.class,  // Interacts with ReflectiveTools
                SHA384Test.class,  // Interacts with ReflectiveTools
                SHA512Test.class,  // Interacts with ReflectiveTools
                RdrandTest.class,  // Has JVM-wide impact
                TestProviderInstallation.class, // Has JVM-wide impact
                ServiceSelfTestMetaTest.class, // Has JVM-wide impact
                // The security manager test *must* come last.
                // It mucks around with Java's internal security
                // settings and can cause coverage (and possibly
                // other tests) to fail in interesting ways.
                SecurityManagerTest.class
                });
        tmp.put("integration", new Class[] {
                LocalHTTPSIntegrationTest.class,
                ExternalHTTPSIntegrationTest.class});

        SUITES_SERIAL = Collections.unmodifiableMap(tmp);
    }

    public static void main(String[] args) throws InitializationError {
        AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
        if (args.length < 2) {
            printUsage();
            System.exit(-1);
        } else if (!args[0].equals("--suite")) {
            printUsage();
            System.exit(-1);
        } else {
            printSystemInfo();
            final String suiteName = args[1];
            final Class[] parallel_classes = SUITES_PARALLEL.get(suiteName);
            final Class[] serial_classes = SUITES_SERIAL.get(suiteName);
            if (parallel_classes == null && serial_classes == null) {
                Set<String> suiteNames = new HashSet<>();
                suiteNames.addAll(SUITES_SERIAL.keySet());
                suiteNames.addAll(SUITES_PARALLEL.keySet());
                System.err.println("Unknown suite: " + suiteName);
                System.err.println("Known suites: " + suiteNames);
                System.exit(-1);
            }

            int runCount = 0;
            long runTime = 0;
            int failureCount = 0;
            int ignoreCount = 0;
            List<Failure> failures = new ArrayList<>();
            final JUnitCore core = new JUnitCore();
            core.addListener(new BasicListener(suiteName, false));

            // TODO: Capture STDOUT/STDERR to nicely bundle output with tests
            // TODO: Capture start and end of each class for bundling and summary
            if (parallel_classes != null) {
                Runner suite = new ParallelComputer(true, true).getSuite(new AllDefaultPossibilitiesBuilder(true), parallel_classes);
                final Request request = Request.runner(suite);

                final Result result = core.run(request);
                runCount += result.getRunCount();
                runTime += result.getRunTime();
                failureCount += result.getFailureCount();
                ignoreCount += result.getIgnoreCount();
                failures.addAll(result.getFailures());
            }

            if (serial_classes != null) {
                final Result result = core.run(Request.classes(serial_classes));
                runCount += result.getRunCount();
                runTime += result.getRunTime();
                failureCount += result.getFailureCount();
                ignoreCount += result.getIgnoreCount();
                failures.addAll(result.getFailures());
            }

            final boolean failed = failureCount > 0;
            System.out.format("%s Suite %s ran %d tests in %.2f seconds with %d failures. (Ignored %d)\n",
                    failed ? FAILED_NOTICE : PASSED_NOTICE,
                    suiteName,
                    runCount,
                    runTime / 1000.0,
                    failureCount,
                    ignoreCount
                    );
            if (failed) {
                System.out.format("%s %s\n", FAILED_NOTICE,
                    failures.stream()
                      .map(f -> f.toString() + "@" + getFailureLocation(f.getException()))
                      .collect(Collectors.toList())
                    );
            }

            System.exit(failed ? -1 : 0);
        }

    }

    private static void printUsage() {
        System.out.println("java TestRunner --suite <suitename>");
    }

    private static void printSystemInfo() {
        final Runtime rt = Runtime.getRuntime();
        System.out.format("System Info(Memory): %d free / %d total (max %d)\n",
                rt.freeMemory(), rt.totalMemory(), rt.maxMemory());
    }

    public static StackTraceElement getFailureLocation(Throwable t) {
        final StackTraceElement[] stackTrace = t.getStackTrace();
        for (StackTraceElement e : stackTrace) {
            if (e.getClassName().startsWith("com.amazon.corretto.crypto.provider.")) {
                return e;
            }
        }
        if (stackTrace.length > 0) {
            return stackTrace[0];
        } else {
            return null;
        }
    }

    public static class BasicListener extends RunListener {
        private final AtomicInteger assumedCount_ = new AtomicInteger(0);
        private final boolean verbose_;
        private final String suiteName_;
        private boolean statusOutput_ = false;
        private volatile boolean alreadyFailed = false;

        public BasicListener(final String suiteName, boolean verbose) {
            suiteName_ = suiteName;
            verbose_ = verbose;
        }

        @Override
        public void testRunStarted(Description description) throws Exception {
            System.out.format("Starting test suite: %s\n", suiteName_);
            System.out.println(description.getChildren());
        }

        @Override
        public void testRunFinished(Result result) throws Exception {
        }

        @Override
        public void testStarted(Description description) throws Exception {
            if (verbose_) {
                printNotice(STARTED_NOTICE, description);
            }
            statusOutput_ = false;
        }

        @Override
        public void testFailure(Failure failure) throws Exception {
            final Throwable exception = failure.getException();
            alreadyFailed = true;
            printNotice(FAILED_NOTICE, failure + " @ " + getFailureLocation(exception));

            // Don't print out traces for Assert.* failures which throw subclasses of AssertionError.
            // Just for thrown exceptions
            if (AssertionError.class.equals(exception.getClass()) ||
                    !(exception instanceof AssertionError)) {
                  System.out.println(failure.getTrace());
              }
              statusOutput_ = true;
        }

        @Override
        public void testFinished(Description description) throws Exception {
            if (!statusOutput_) {
                printNotice(PASSED_NOTICE, description);
                statusOutput_ = true;
            }
        }

        @Override
        public void testAssumptionFailure(Failure failure) {
            assumedCount_.incrementAndGet();
            if (!statusOutput_) {
                printNotice(ASSUMPTION_FAILED_NOTICE, failure);
                statusOutput_ = true;
            }
        }

        @Override
        public void testIgnored(Description description) throws Exception {
            printNotice(IGNORED_NOTICE, description);
            statusOutput_ = true;
        }       

        private void printNotice(final String notice, final Object description) {
            System.out.format("%s%s %s\n",
                alreadyFailed ? ALREADY_FAILED_NOTICE : NOT_YET_FAILED_NOTICE,
                notice,
                description);
        }
    }
}
