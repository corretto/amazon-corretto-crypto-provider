// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.HpkeTestSuite.cipher;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Shared read-only keys and serialized access to a Cipher's context and sequence number. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class HpkeThreadStormTest {
  private static final int THREADS = 8;
  private static final int ITERATIONS = 25;

  private static byte[] message(final int thread, final int i) {
    return ("thread " + thread + " message " + i).getBytes(StandardCharsets.UTF_8);
  }

  private interface ThreadTask {
    void run(int thread) throws Exception;
  }

  private static void storm(final ThreadTask task) throws Exception {
    final ExecutorService executor = Executors.newFixedThreadPool(THREADS);
    try {
      final CountDownLatch start = new CountDownLatch(1);
      final List<Future<Void>> futures = new ArrayList<>();
      for (int t = 0; t < THREADS; t++) {
        final int thread = t;
        futures.add(
            executor.submit(
                (Callable<Void>)
                    () -> {
                      start.await();
                      task.run(thread);
                      return null;
                    }));
      }
      start.countDown();
      for (final Future<Void> future : futures) {
        future.get(5, TimeUnit.MINUTES);
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void sharedKeyPairWithCiphersPerMessage(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    storm(
        thread -> {
          for (int i = 0; i < ITERATIONS; i++) {
            final Cipher sender = cipher();
            sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
            final byte[] ct = sender.doFinal(message(thread, i));
            final Cipher recipient = cipher();
            recipient.init(
                Cipher.DECRYPT_MODE,
                kp.getPrivate(),
                suite.spec().withEncapsulation(sender.getIV()));
            assertArrayEquals(message(thread, i), recipient.doFinal(ct));
          }
        });
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void longLivedCiphersPerThread(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    storm(
        thread -> {
          final Cipher sender = cipher();
          sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
          final Cipher recipient = cipher();
          recipient.init(
              Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(sender.getIV()));
          for (int i = 0; i < ITERATIONS; i++) {
            assertArrayEquals(
                message(thread, i), recipient.doFinal(sender.doFinal(message(thread, i))));
          }
        });
  }

  /**
   * Tests the internal lock by sharing a sender and retrying unordered ciphertexts until they open.
   * Failed opens must preserve sequence numbers. Applications must not share Ciphers across
   * threads; the JCA does not support it.
   */
  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void sharedSenderCipher(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final Queue<byte[][]> sealed = new ConcurrentLinkedQueue<>();
    storm(
        thread -> {
          for (int i = 0; i < ITERATIONS; i++) {
            final byte[] pt = message(thread, i);
            sealed.add(new byte[][] {pt, sender.doFinal(pt)});
          }
        });
    assertEquals(THREADS * ITERATIONS, sealed.size());

    final Cipher recipient = cipher();
    recipient.init(
        Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(sender.getIV()));
    final List<byte[][]> remaining = new ArrayList<>(sealed);
    while (!remaining.isEmpty()) {
      boolean opened = false;
      for (final Iterator<byte[][]> it = remaining.iterator(); it.hasNext(); ) {
        final byte[][] entry = it.next();
        try {
          assertArrayEquals(entry[0], recipient.doFinal(entry[1]));
        } catch (final AEADBadTagException ex) {
          continue;
        }
        it.remove();
        opened = true;
        break;
      }
      assertTrue(opened, remaining.size() + " ciphertexts left and none opens");
    }
  }
}
