// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetInternalClass;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.SelfTestResult;
import com.amazon.corretto.crypto.provider.SelfTestStatus;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class LibCryptoRngTest {
  private SecureRandom rnd;

  private static SecureRandom getLibCryptoRng() {
    try {
      return SecureRandom.getInstance("LibCryptoRng", AmazonCorrettoCryptoProvider.INSTANCE);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @BeforeEach
  public void setup() throws NoSuchAlgorithmException {
    rnd = getLibCryptoRng();
  }

  @AfterEach
  public void teardown() {
    rnd = null;
  }

  private void ensureRngGeneratesUniqueValues(SecureRandom rng) {
    final int initial = rng.nextInt();
    for (int trial = 0; trial < 10; trial++) {
      if (initial != rng.nextInt()) {
        return;
      }
    }
    fail("Failed to find a different value");
  }

  @Test
  public void testGetInstance() throws NoSuchAlgorithmException {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    ensureRngGeneratesUniqueValues(SecureRandom.getInstance("DEFAULT", TestUtil.NATIVE_PROVIDER));
    ensureRngGeneratesUniqueValues(
        SecureRandom.getInstance("LibCryptoRng", TestUtil.NATIVE_PROVIDER));
  }

  // A common mistake is when filling arrays to not do it properly and leave
  // zero gaps. To detect this, we'll generate arrays of different lengths
  // and check to see if certain bytes are always zero
  @Test
  public void testNextBytes() {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    for (int size = 0; size < 64; size++) {
      final byte[] checkArr = new byte[size];
      final byte[] arr = new byte[size];
      for (int trial = 0; trial < 4; trial++) {
        rnd.nextBytes(arr);
        for (int x = 0; x < size; x++) {
          checkArr[x] = (byte) (checkArr[x] | arr[x]);
        }
      }
      for (int x = 0; x < size; x++) {
        assertTrue(
            0 != checkArr[x], "Check array size " + size + " position " + x + " is equal to zero");
      }
    }
  }

  // A common mistake is when filling arrays to not do it properly and leave
  // zero gaps. To detect this, we'll generate arrays of different lengths
  // and check to see if certain bytes are always zero
  @Test
  public void testGenerateSeed() {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    for (int size = 0; size < 64; size++) {
      final byte[] checkArr = new byte[size];
      for (int trial = 0; trial < 4; trial++) {
        final byte[] arr = rnd.generateSeed(size);
        for (int x = 0; x < size; x++) {
          checkArr[x] = (byte) (checkArr[x] | arr[x]);
        }
      }
      for (int x = 0; x < size; x++) {
        assertTrue(
            0 != checkArr[x], "Check array size " + size + " position " + x + " is equal to zero");
      }
    }
  }

  // There really isn't a good way to test random numbers.
  // So we generate a few, ensure they aren't all the same
  // value and don't throw exceptions
  @Test
  public void testInt() {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    ensureRngGeneratesUniqueValues(rnd);
  }

  @Test
  public void testLong() {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
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
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
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
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    // prove we can request very large amounts of data, even if it requires
    // reseeding in the middle
    final byte[] bytes = new byte[12288];
    rnd.nextBytes(bytes);
    // Ensure that the resulting bytes haven't been left at zero
    // Probablistically, this will pass.
    final int retries = 5;
    for (int i = 0; i < retries; i++) {
      byte[] tests = new byte[3];
      tests[0] = bytes[8192];
      tests[1] = bytes[8193];
      tests[2] = bytes[12287];
      rnd.nextBytes(bytes);
      boolean passed = true;
      passed &= (tests[0] != bytes[8192]);
      passed &= (tests[1] != bytes[8193]);
      passed &= (tests[2] != bytes[12287]);
      if (passed) {
        return;
      }
    }
    fail(String.format("Exceeded %d retries, should investigate this.", retries));
  }

  @Test
  public void selfTest() throws Throwable {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    final Class<?> libCryptoRngClass =
        Class.forName("com.amazon.corretto.crypto.provider.LibCryptoRng");
    Class<?> spi = sneakyGetInternalClass(libCryptoRngClass, "SPI");
    SelfTestResult result = sneakyInvoke(spi, "runSelfTest");
    assertEquals(SelfTestStatus.PASSED, result.getStatus());
  }

  @Test
  public void manyRequestsTest() throws Throwable {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    final SecureRandom rng = getLibCryptoRng();
    int MAX_REQUESTS_BEFORE_RESEED = 1 << 12;
    int MAX_BYTES_BEFORE_RESEED = 1 << 16;
    int BYTES_PER_REQUEST = Math.max(1, (MAX_BYTES_BEFORE_RESEED / MAX_REQUESTS_BEFORE_RESEED));
    byte[] rngOutputBuffer = new byte[BYTES_PER_REQUEST];

    // Ensure that we can successfully reseed the RNG a few times
    int RESEED_COUNT = 3;
    for (long i = 0; i < (RESEED_COUNT * MAX_REQUESTS_BEFORE_RESEED) + 1; i++) {
      rng.nextBytes(rngOutputBuffer);
    }
  }

  @Test
  public void multithreadedTest() throws Throwable {
    assumeMinimumVersion("2.0.0", TestUtil.NATIVE_PROVIDER);
    final SecureRandom sharedRng = getLibCryptoRng();
    int NUM_THREADS = 100;
    final Set<Long> rngOutputs = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());
    List<Thread> threadList = new ArrayList<Thread>(NUM_THREADS);

    // Call sharedRng.nextLong() to ensure sharedRng initialization happens in main thread
    rngOutputs.add(sharedRng.nextLong());

    // Create our threads, but don't start them yet.
    for (int i = 0; i < NUM_THREADS; i++) {
      Thread thread =
          new Thread() {
            public void run() {
              // For each thread, add a random long generated from the shared RNG, and one from a
              // thread-local RNG
              rngOutputs.add(sharedRng.nextLong());
              rngOutputs.add(getLibCryptoRng().nextLong());
            }
          };
      threadList.add(thread);
    }

    // Start all the threads at once, as close together as possible
    for (Thread t : threadList) {
      t.start();
    }

    // Wait for all the threads to complete
    for (Thread t : threadList) {
      t.join();
    }

    // Ensure that every long generated by each RNG is unique.
    assertEquals(rngOutputs.size(), (1 + (NUM_THREADS * 2)));
  }
}
