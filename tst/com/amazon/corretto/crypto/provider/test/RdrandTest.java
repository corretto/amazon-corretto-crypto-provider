// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Function;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.After;
import org.junit.AssumptionViolatedException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import com.amazon.corretto.crypto.provider.AesCtrDrbg;
import com.amazon.corretto.crypto.provider.RuntimeCryptoException;

@RunWith(Suite.class)
@Suite.SuiteClasses({RdrandTest.PerRNG.class, RdrandTest.Global.class})
public class RdrandTest {
    static Class<?> PRIVILEGED_TEST_HOOKS;

    static {
        try {
            PRIVILEGED_TEST_HOOKS = RdrandTest.class.getClassLoader()
                                              .loadClass("com.amazon.corretto.crypto.provider.PrivilegedTestHooks");
        } catch (ClassNotFoundException t) {
            throw new RuntimeException(t);
        }
        assumeTrue(NativeTestHooks.hasNativeHooks());
    }

    private static void setRNGSuccessPattern(final long pattern) throws Throwable {
        if (!(Boolean)sneakyInvoke(PRIVILEGED_TEST_HOOKS, "set_rng_success_pattern", pattern)) {
            throw new AssumptionViolatedException("Test hooks unavailable");
        }
    }

    private static void resetSuccessPattern() throws Throwable {
        sneakyInvoke(PRIVILEGED_TEST_HOOKS, "set_rng_success_pattern", ~0L);
    }

    public static class Global {
        @Before
        public void setUp() throws Exception {
            assumeTrue(AmazonCorrettoCryptoProvider.isRdRandSupported());
            assumeTrue(NativeTestHooks.hasNativeHooks());
        }

        @After
        public void tearDown() throws Throwable {
            if (NativeTestHooks.hasNativeHooks()) {
                resetSuccessPattern();
            }
        }


        @Test
        public void whenRDRandBroken_RNGDoesNotProvideData() throws Throwable {
            AesCtrDrbg rng = new AesCtrDrbg();

            setRNGSuccessPattern(0);

            byte[] buf = new byte[1];
            assertThrows(RuntimeCryptoException.class, () -> rng.nextBytes(buf));
            assertEquals(0, buf[0]);
        }

        @Test
        public void whenRDSeedBroken_RNGConstructionFails() throws Throwable {
            assumeTrue(NativeTestHooks.hasRdseed());
            assumeTrue(sneakyInvoke(PRIVILEGED_TEST_HOOKS, "break_rdseed"));

            byte[] buf = new byte[1];
            assertThrows(RuntimeCryptoException.class, () -> new AesCtrDrbg().nextBytes(buf));
            assertEquals(0, buf[0]);
        }
    }

    @RunWith(Parameterized.class)
    public static class PerRNG {
        Function<byte[], Boolean> rng;

        @Parameterized.Parameters(name = "{index}: {0}")
        public static Iterable<Object[]> data() {
            ArrayList<Object[]> params = new ArrayList<>();
            if (!NativeTestHooks.hasNativeHooks()) {
                return params;
            }

            if (AmazonCorrettoCryptoProvider.isRdRandSupported()) {
                params.add(new Object[]{"rdrand", (Function<byte[], Boolean>) NativeTestHooks::rdrand});
            }

            if (NativeTestHooks.hasRdseed()) {
                params.add(new Object[]{"rdseed", (Function<byte[], Boolean>) NativeTestHooks::rdseed});
            }

            return params;
        }

        public PerRNG(String description, Function<byte[], Boolean> rng) throws Exception {
            this.rng = rng;
        }

        @Before
        public void setUp() {
            assumeTrue("RDRAND unavailable", AmazonCorrettoCryptoProvider.isRdRandSupported());
        }

        @After
        public void tearDown() throws Throwable {
            resetSuccessPattern();
        }

        @Test
        public void rng_returns_unique_data() {
            assert_returns_unique_data();
        }

        @Test
        public void when_rng_broken_no_data_returned() throws Throwable {
            // When all calls fail, we shouldn't return any data
            setRNGSuccessPattern(0L);

            assertFails(1);
            assertFails(1);
            assertFails(16);
            assertFails(16);


            // When a 64-bit chunk in the middle of a larger get fails, we shouldn't return any data

            setRNGSuccessPattern(0b011L);
            assertTrue(rng.apply(new byte[1]));
            assertFails(16);

            // When the final non-full-long-sized chunk fails, we shouldn't return any data

            setRNGSuccessPattern(0b011L);
            assertTrue(rng.apply(new byte[1]));
            assertFails(15);
        }

        @Test
        public void when_rng_flaky_retry_is_successful() throws Throwable {
            // 1010 ... = 0xAAAA...
            setRNGSuccessPattern(0xAAAA_AAAA_AAAA_AAAAL);

            assert_returns_unique_data();
            assert_returns_unique_data();
        }

        private void assert_returns_unique_data() {
            byte[] buf1 = new byte[16];
            assertTrue(rng.apply(buf1));
            byte[] buf2 = new byte[16];
            assertTrue(rng.apply(buf2));

            assertFalse(Arrays.equals(buf1, buf2));

            boolean sawDifference = false;
            buf1 = new byte[1];
            buf2 = new byte[1];

            for (int i = 0; i < 16; i++) {
                assertTrue(rng.apply(buf1));
                assertTrue(rng.apply(buf2));

                sawDifference = buf1[0] != buf2[0];
                if (sawDifference) {
                    break;
                }
            }

            assertTrue(sawDifference);
        }

        private void assertFails(int array_size) {
            byte[] arr = new byte[array_size];

            assertFalse(rng.apply(arr));

            assertArrayEquals(new byte[array_size], arr);
        }

    }
}
