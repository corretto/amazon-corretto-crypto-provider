// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetField;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetInternalClass;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.After;
import org.junit.Assume;
import org.junit.AssumptionViolatedException;
import org.junit.Before;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.AesCtrDrbg;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;

public class AesCtrDrbgTest {
    private AesCtrDrbg rnd;

    @Before
    public void setup() {
        Assume.assumeTrue("RDRand must be supported", AmazonCorrettoCryptoProvider.isRdRandSupported());

        rnd = new AesCtrDrbg();
    }

    @After
    public void teardown() {
        rnd = null;
    }

    @Test
    public void whenAlgorithmParametersPassed_constructionFails() throws Exception {
        // Java 9 introduces support for parameters objects passed to SecureRandom instances. Currently we reject those
        // parameters unconditionally, this test checks that they're rejected correctly.

        // Because SecureRandomParameters is only available in Java 9, we need to use reflection to try to find it.
        ClassLoader loader = AesCtrDrbgTest.class.getClassLoader();

        Class<?> secureRandomParams;
        try {
            secureRandomParams = loader.loadClass("java.security.SecureRandomParameters");
        } catch (ClassNotFoundException e) {
            throw new AssumptionViolatedException("SecureRandomParameters not available in pre-java-9");
        }

        Class<?> drbgParamsClass = loader.loadClass("java.security.DrbgParameters");
        Class<?> capabilityClass = loader.loadClass("java.security.DrbgParameters$Capability");
        Object PR_AND_RESEED = capabilityClass.getField("PR_AND_RESEED").get(null);
        Method instantiation
                = drbgParamsClass.getMethod("instantiation", int.class, capabilityClass, byte[].class);
        Method getInstance
                = SecureRandom.class.getMethod("getInstance", String.class, secureRandomParams, Provider.class);
        Object params = instantiation.invoke(null, 256, PR_AND_RESEED, new byte[1]);

        try {
            getInstance.invoke(null, "NIST800-90A/AES-CTR-256", params, AmazonCorrettoCryptoProvider.INSTANCE);
            fail("Expected exception");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof NoSuchAlgorithmException);
        }
    }

    // A common mistake it when filling arrays to not do it properly and leave
    // zero gaps. To detect this, we'll generate arrays of different lengths
    // and check to see if certain bytes are always zero
    @Test
    public void testNextBytes() {
        for (int size = 0; size < 64; size++) {
            final byte[] checkArr = new byte[size];
            final byte[] arr = new byte[size];
            for (int trial = 0; trial < 4; trial++) {
                rnd.nextBytes(arr);
                System.out.println(Hex.encodeHex(arr));
                for (int x = 0; x < size; x++) {
                    checkArr[x] = (byte) (checkArr[x] | arr[x]);
                }
            }
            for (int x = 0; x < size; x++) {
                assertTrue("Check array size " + size + " position " + x + " is equal to zero",
                        0 != checkArr[x]);
            }
        }
    }

    // A common mistake it when filling arrays to not do it properly and leave
    // zero gaps. To detect this, we'll generate arrays of different lengths
    // and check to see if certain bytes are always zero
    @Test
    public void testGenerateSeed() {
        for (int size = 0; size < 64; size++) {
            final byte[] checkArr = new byte[size];
            for (int trial = 0; trial < 4; trial++) {
                final byte[] arr = rnd.generateSeed(size);
                System.out.println(Hex.encodeHex(arr));
                for (int x = 0; x < size; x++) {
                    checkArr[x] = (byte) (checkArr[x] | arr[x]);
                }
            }
            for (int x = 0; x < size; x++) {
                assertTrue("Check array size " + size + " position " + x + " is equal to zero",
                        0 != checkArr[x]);
            }
        }
    }

    // There really isn't a good way to test random numbers.
    // So we generate a few, ensure they aren't all the same
    // value and don't throw exceptions
    @Test
    public void testInt() {
        final int initial = rnd.nextInt();
        for (int trial = 0; trial < 10; trial++) {
            if (initial != rnd.nextInt()) {
                return;
            }
        }
        fail("Failed to find a different value");
    }

    @Test
    public void testLong() {
        final long initial = rnd.nextLong();
        for (int trial = 0; trial < 10; trial++) {
            if (initial != rnd.nextLong()) {
                return;
            }
        }
        fail("Failed to find a different value");
    }

    @Test
    public void reseed() {
        // Just ensure this doesn't crash
        rnd.setSeed(new byte[0]);
        rnd.setSeed(new byte[1]);
        rnd.setSeed(new byte[16]);
        rnd.setSeed(new byte[20]);
        rnd.setSeed(new byte[24]);
        rnd.setSeed(new byte[32]);
        rnd.setSeed(new byte[48]);
        rnd.setSeed(new byte[64]);
    }

    @Test
    public void largeRequest() {
        // prove we can request very large amounts of data, even if it requires
        // reseeding in the middle
        final byte[] bytes = new byte[12288];
        rnd.nextBytes(bytes);
        // Ensure that the resulting bytes haven't been left at zero
        // Probablistically, this will pass.
        byte[] tests = new byte[3];
        tests[0] = bytes[8192];
        tests[1] = bytes[8193];
        tests[2] = bytes[12287];
        rnd.nextBytes(bytes);
        assertTrue(tests[0] != bytes[8192]);
        assertTrue(tests[1] != bytes[8193]);
        assertTrue(tests[2] != bytes[12287]);
    }

    @Test
    public void selfTest() throws Throwable {
        Class<?> spi = sneakyGetInternalClass(AesCtrDrbg.class, "SPI");
        SelfTestResult result = (SelfTestResult) sneakyInvoke(spi, "runSelfTest");
        assertEquals(SelfTestStatus.PASSED, result.getStatus());
    }

    @Test
    public void nistTestVectors() throws ReflectiveOperationException, SecurityException,
            IOException, DecoderException {
        final Constructor<AesCtrDrbg> testConstructor = getTestConstructor();
        int tests = 0;

        try (final Scanner in = new Scanner(TestUtil.sneakyGetTestData("ctr-drbg.txt"), 
                                            StandardCharsets.US_ASCII.name())) {
            while (in.hasNext()) {
                tests++;
                final int bytesGenerated = in.nextInt() / 8;
                final byte[] seed = Hex.decodeHex(in.next().toCharArray());
                final byte[] entropy = Hex.decodeHex(in.next().toCharArray());
                final byte[] expected = Hex.decodeHex(in.next().toCharArray());

                final AesCtrDrbg drbg = testConstructor.newInstance(entropy, seed);
                final byte[] output = new byte[bytesGenerated];
                drbg.nextBytes(output);
                drbg.nextBytes(output);
                assertArrayEquals("Line " + tests, expected, output);
            }

        } finally {
            System.out.println("Completed " + tests + " test vectors");
        }
    }

    private static final Object getNativeState(final Object drbg) {
      try {
        final Object spi = sneakyGetField(drbg, "secureRandomSpi");
        return sneakyInvoke(spi, "getState");
      } catch (final Throwable t) {
        throw new RuntimeException(t);
      }
    };

    @Test
    public void usesThreadLocal() throws Throwable {
      final byte[] seed = new byte[48];
      Arrays.fill(seed, (byte) 0xAF);
      final Constructor<AesCtrDrbg> testConstructor = getTestConstructor();
      final Object stateThread1_1 = getNativeState(new AesCtrDrbg());
      final Object stateThread1_2 = getNativeState(new AesCtrDrbg());
      final Object stateThread1_SelfTest1 = getNativeState(testConstructor.newInstance(new byte[128], seed));
      final Object stateThread1_3 = getNativeState(new AesCtrDrbg());
      final Object stateThread1_SelfTest2 = getNativeState(testConstructor.newInstance(new byte[128], seed));
      final Object stateThread1_4 = getNativeState(new AesCtrDrbg());

      assertSame("SecureRandom on same thread should use same state",
          stateThread1_1, stateThread1_2);
      assertSame("SecureRandom on same thread should use same state",
          stateThread1_1, stateThread1_3);
      assertSame("SecureRandom on same thread should use same state",
          stateThread1_1, stateThread1_4);
      assertNotSame("SecureRandom on same thread should not use test state",
          stateThread1_1, stateThread1_SelfTest1);
      assertNotSame("SecureRandom on same thread should not use test state",
          stateThread1_1, stateThread1_SelfTest2);
      assertNotSame("SecureRandom test states should be different",
          stateThread1_SelfTest1, stateThread1_SelfTest2);

      final TestThreadLocalThread t = new TestThreadLocalThread();
      t.start();
      t.join();

      assertSame("SecureRandom on same thread should use same state",
          t.stateThread2_1, t.stateThread2_2);
      assertSame("SecureRandom on same thread should use same state",
          t.stateThread2_1, t.stateThread2_3);
      assertSame("SecureRandom on same thread should use same state",
          t.stateThread2_1, t.stateThread2_4);
      assertNotSame("SecureRandom on same thread should not use test state",
          t.stateThread2_1, t.stateThread2_SelfTest1);
      assertNotSame("SecureRandom on same thread should not use test state",
          t.stateThread2_1, t.stateThread2_SelfTest2);
      assertNotSame("SecureRandom test states should be different",
          t.stateThread2_SelfTest1, t.stateThread2_SelfTest2);

      assertNotSame("SecureRandom states on different threads should be different",
          stateThread1_1, t.stateThread2_1);
      assertNotSame("SecureRandom states on different threads should be different",
          stateThread1_SelfTest1, t.stateThread2_SelfTest1);
    }

    final static class TestThreadLocalThread extends Thread {
      public Object stateThread2_1;
      public Object stateThread2_2;
      public Object stateThread2_SelfTest1;
      public Object stateThread2_3;
      public Object stateThread2_SelfTest2;
      public Object stateThread2_4;

      @Override
      public void run() {
          try {
              final byte[] seed = new byte[48];
                  Arrays.fill(seed, (byte) 0xAF);
                  final Constructor<AesCtrDrbg> testConstructor = getTestConstructor();
                  stateThread2_1 = getNativeState(new AesCtrDrbg());
                  stateThread2_2 = getNativeState(new AesCtrDrbg());
                  stateThread2_SelfTest1 =
                      getNativeState(testConstructor.newInstance(new byte[128], seed));
                  stateThread2_3 = getNativeState(new AesCtrDrbg());
                  stateThread2_SelfTest2 =
                      getNativeState(testConstructor.newInstance(new byte[128], seed));
                  stateThread2_4 = getNativeState(new AesCtrDrbg());
          } catch (final Throwable ex) {
              ex.printStackTrace();
          }
      }
    }

    @Test
    public void testRdRandWorks() throws ReflectiveOperationException {
        // This test constructs two DRBGs with identical seeds and then ensures that they give
        // different results.
        // The only way for them to (correctly) deviate is if they are getting different data from
        // the
        // native RDRAND calls.
        final Constructor<AesCtrDrbg> testConstructor = getTestConstructor();
        final byte[] seed = new byte[48];
        // Our sanity check detects all-zero seeds; frob the seed a little to make sure we don't hit that.
        seed[0] = 1;
        final AesCtrDrbg rng1 = testConstructor.newInstance(null, seed);
        final AesCtrDrbg rng2 = testConstructor.newInstance(null, seed);
        final byte[] data1 = new byte[64];
        final byte[] data2 = new byte[64];
        rng1.nextBytes(data1);
        rng2.nextBytes(data2);

        assertFalse(Arrays.equals(data1, data2));
    }

    @SuppressWarnings("unchecked")
    private static Constructor<AesCtrDrbg> getTestConstructor() {
        Constructor<AesCtrDrbg> testConstructor = null;
        for (Constructor<?> tmp : AesCtrDrbg.class.getDeclaredConstructors()) {
            if (tmp.getParameterCount() == 2) {
                testConstructor = (Constructor<AesCtrDrbg>) tmp;
            }
        }
        testConstructor.setAccessible(true);
        return testConstructor;
    }
}
