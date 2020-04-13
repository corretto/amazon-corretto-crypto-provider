// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class JanitorTest {
    private static final Constructor<?> ctor_Janitor;
    private static final Method m_register;
    private static final Method m_clean;

    static {
        try {
            Class<?> janitorClass = JanitorTest.class.getClassLoader().loadClass(
                    "com.amazon.corretto.crypto.provider.Janitor"
            );

            ctor_Janitor = janitorClass.getDeclaredConstructor(ThreadFactory.class);
            ctor_Janitor.setAccessible(true);

            m_register = janitorClass.getDeclaredMethod("register", Object.class, Runnable.class);
            m_register.setAccessible(true);

            m_clean = JanitorTest.class.getClassLoader().loadClass(
                    "com.amazon.corretto.crypto.provider.Janitor$Mess"
            ).getDeclaredMethod("clean");
            m_clean.setAccessible(true);
        } catch (ReflectiveOperationException ex) {
            throw new AssertionError(ex);
        }
    }

    private Object referent;
    private ThreadGroup threadGroup;

    public JanitorTest() throws Exception {
        threadGroup = new ThreadGroup("Cleaner thread group");
    }

    @Before
    public void setUp() throws Exception {
        assertFalse("Cleaners running at startup", isCleanerRunning());
    }

    @After
    public void tearDown() throws Exception {
        referent = null;

        // Wait for any stray janitors to clean up
        eventually("tearDown: Janitors stopped", () -> !isCleanerRunning());
        threadGroup = null;
    }

    @Test
    public void backpressure_eventuallyCleans() throws Exception {
        try {
            // Make sure everything is on the same stripe
            System.setProperty("com.amazon.corretto.crypto.provider.janitor.stripes", "1");

            CyclicBarrier barrier = new CyclicBarrier(2);

            // Disable the background thread to artifically increase the amount of backpressure activity
            Object janitor = ctor_Janitor.newInstance((ThreadFactory) task -> new Thread(() -> {
            }));

            CompletableFuture<Void> f = CompletableFuture.runAsync(() -> {
                try {
                    barrier.await();
                    AtomicBoolean b = new AtomicBoolean(false);
                    m_register.invoke(janitor, new Object(), (Runnable) () -> b.set(true));

                    for (int i = 0; i < 1_000_000 && !b.get(); i++) {
                        if ((i % 10) == 0) {
                            System.gc();
                        }
                        m_register.invoke(janitor, new Object(), (Runnable) () -> {});
                    }

                    barrier.await();
                    barrier.await();

                    assertTrue(b.get());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            barrier.await();
            barrier.await();

            // At this point we've churned through all the stripes in the other thread (which is still running, but blocked
            // on the cyclic barrier).

            // We'd like to make sure the other thread dropped the stripe locks, so make sure backpressure processing works
            // here as well.

            AtomicBoolean b = new AtomicBoolean(false);
            m_register.invoke(janitor, new Object(), (Runnable) () -> b.set(true));

            for (int i = 0; i < 1_000_000 && !b.get(); i++) {
                if ((i % 10) == 0) {
                    System.gc();
                }
                m_register.invoke(janitor, new Object(), (Runnable) () -> {});
            }
            assertTrue(b.get());

            barrier.await();

            // Make sure the other thread completed successfully
            f.get();
        } finally {
            System.clearProperty("com.amazon.corretto.crypto.provider.janitor.stripes");
        }
    }

    @Test
    public void explicitClean_cleansOnce() throws Exception {
        Object janitor = newJanitor();
        referent = new Object();
        int[] invoked = new int[1];
        Object mess = m_register.invoke(janitor, referent, (Runnable)() -> invoked[0]++);

        never("Invoked too early", () -> invoked[0] > 0);
        m_clean.invoke(mess);
        never("Invoked multiple times or not at all", () -> invoked[0] != 1);
    }

    @Test
    public void implicitClean_cleansOnce() throws Exception {
        Object janitor = newJanitor();
        referent = new Object();
        int[] invoked = new int[1];
        m_register.invoke(janitor, referent, (Runnable)() -> invoked[0]++);

        never("Invoked too early", () -> invoked[0] > 0);
        referent = null;
        eventually("Cleanup invoked", () -> invoked[0] == 1);
        never("Cleanup invoked multiple times", () -> invoked[0] != 1);
    }

    @Test
    public void janitor_whenReleased_shutsDownCleanly() throws Exception {
        Object janitor = newJanitor();
        assertTrue(isCleanerRunning());

        referent = new Object();
        m_register.invoke(janitor, referent, (Runnable)()->{});
        janitor = null;

        // the outstanding referent keeps the janitor alive
        never("Janitor stays alive", () -> !isCleanerRunning());

        referent = null;
        // Now the janitor can be cleaned up
        eventually("Janitor shuts down", () -> !isCleanerRunning());
    }

    @Test
    public void janitor_whenCleanerExplicitlyInvoked_shutsDownCleanly() throws Exception {
        Object janitor = newJanitor();
        assertTrue(isCleanerRunning());

        referent = new Object();
        Object mess = m_register.invoke(janitor, referent, (Runnable)()->{});
        janitor = null;

        // the outstanding referent keeps the janitor alive
        never("Janitor stays alive", () -> !isCleanerRunning());

        m_clean.invoke(mess);
        // Now the janitor can be cleaned up
        eventually("Janitor shuts down", () -> !isCleanerRunning());
    }

    static class Referent {}

    @Test
    public void stressTest() throws Exception {
        /*
         * This test races multiple threads, each of which continually create messes, and then clean up some (but not
         * all) of them at random. Periodically, a GC is explicitly triggered.
         *
         * At the end of the test, we assert that every mess is cleaned up _exactly_ once.
         */

        int numThreads = 8;
        int numRefsPerThread = 1_000_000;
        int gcCycle = 100_000;
        // Put this in an array so it can be nulled out later, but doesn't prevent us from using it in lambdas
        Object[] janitor = new Object[] { newJanitor() };

        AtomicLong outstandingMesses = new AtomicLong();

        AtomicBoolean sawExtraCleanup = new AtomicBoolean(false);

        CyclicBarrier barrier = new CyclicBarrier(numThreads + 1);

        Thread[] threads = new Thread[numThreads];
        for (int tid = 0; tid < threads.length; tid++) {
            final int tid_ = tid;
            threads[tid] = new Thread(
                    () -> {
                        try {
                            ArrayList<Object> pendingCleanable = new ArrayList<>();
                            barrier.await();

                            for (int i = 0; i < numRefsPerThread; i++) {
                                if (tid_ == 0 && i > 0 && (i % gcCycle) == 0) {
                                    // Perform a periodic GC; we trigger this only on the first thread to avoid excessive
                                    // GCs.
                                    System.gc();
                                }

                                long newRefId = ThreadLocalRandom.current().nextLong();

                                // We use this lock to ensure that the mess cleanup routine doesn't run before we add
                                // the mess to the outstandingMesses map.
                                Object messLock = new Object();

                                synchronized (messLock) {
                                        try {
                                        AtomicBoolean doubleRemoval = new AtomicBoolean(false);
                                        Object mess = m_register.invoke(
                                                janitor[0],
                                                new Referent(),
                                                (Runnable) () -> {
                                                    synchronized (messLock) {
                                                        //outstandingMesses.remove(newRefId);
                                                        //if (outstandingMesses.remove(newRefId) == null) {
                                                        if (doubleRemoval.getAndSet(true)) {
                                                            sawExtraCleanup.set(true);
                                                        } else {
                                                            outstandingMesses.decrementAndGet();
                                                        }
                                                    }
                                                }
                                        );

                                        pendingCleanable.add(mess);
                                        outstandingMesses.incrementAndGet();
                                        //return mess;
                                    } catch (Exception e) {
                                        throw new RuntimeException(e);
                                    }
                                }

                                if ((i & 1) == 1 && !pendingCleanable.isEmpty()) {
                                    // Pick a random ref to delete
                                    int index = ThreadLocalRandom.current().nextInt(pendingCleanable.size());
                                    Object cleanable = pendingCleanable.get(index);

                                    if (index != pendingCleanable.size() - 1) {
                                        // swap the last entry with the removed entry
                                        pendingCleanable.set(index,
                                                             pendingCleanable.remove(pendingCleanable.size() - 1));
                                    }

                                    try {
                                        m_clean.invoke(cleanable);
                                    } catch (Throwable t) {
                                        throw new RuntimeException(t);
                                    }
                                }
                            }

                            barrier.await();
                        } catch (Throwable t) {
                            t.printStackTrace();
                            Thread.currentThread().interrupt();
                            try {
                                // break the barrier
                                barrier.await();
                            } catch (Exception e) {
                                // expected
                            }
                        }
                    }
            );
        }

        for (int i = 0; i < threads.length; i++) {
            threads[i].start();
        }

        barrier.await();
        barrier.await();

        eventually("All messes cleaned", () -> {
            System.out.println("Remaining: " + outstandingMesses.get());
            return outstandingMesses.get() == 0;
        });

        janitor[0] = null;

        eventually("Cleaner shut down", () -> !isCleanerRunning());

        assertFalse("Saw duplicate cleanups on the same mess", sawExtraCleanup.get());
    }

    @Test
    public void testStripeCountOverride() throws Throwable {
        assertStripeCount(1, 1);
        assertStripeCount(2, 2);
        assertStripeCount(3, 4);
        assertStripeCount(7, 8);
        assertStripeCount(8, 8);
        assertStripeCount(9, 16);

        TestUtil.assertThrows(IllegalArgumentException.class, () -> assertStripeCount(0, 1));
        TestUtil.assertThrows(IllegalArgumentException.class, () -> assertStripeCount(-1, 1));
        TestUtil.assertThrows(IllegalArgumentException.class, () -> assertStripeCount(Integer.MIN_VALUE, 1));
    }

    private void assertStripeCount(final int requestedCount, final int expectedCount) throws Throwable {
        System.setProperty("com.amazon.corretto.crypto.provider.janitor.stripes", "" + requestedCount);

        try {
            Object janitor = newJanitor();

            assertEquals(expectedCount, TestUtil.sneakyInvoke_int(janitor, "getStripeCount"));
        } finally {
            System.clearProperty("com.amazon.corretto.crypto.provider.janitor.stripes");
        }
    }

    boolean isCleanerRunning() {
        return threadGroup.enumerate(new Thread[1], true) > 0;
    }

    private Object newJanitor() throws Exception {
        try {
            return ctor_Janitor.newInstance((ThreadFactory)(task -> new Thread(threadGroup, task)));
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();

            if (cause instanceof Error) throw (Error)cause;
            if (cause instanceof Exception) throw (Exception)cause;
            throw new Error(cause);
        }
    }

    void eventually(String description, Supplier<Boolean> predicate) throws InterruptedException {
        for (int i = 0; i < 250; i++) {
            if (predicate.get()) {
                return; // ok
            }

            if (i < 3 || (i % 20) == 0) {
                // Don't do too many GCs, or we end up spending all our time GCing and not letting the
                // cleaner-under-test run
                System.gc();
            }
            wake();

            Thread.sleep(50);
        }

        fail("Predicate did not become true: " + description);
    }

    void never(String description, Supplier<Boolean> predicate) throws InterruptedException {
        // Make sure it's false before any GCs happen too - otherwise we can miss bugs in the test suite itself.
        assertFalse(description, predicate.get());

        for (int i = 0; i < 3; i++) {
            System.gc();
            wake();
            Thread.sleep(100);
            assertFalse(description, predicate.get());
        }
    }

    private void wake() {
        // wake up the cleanup thread if it's alive
        Thread[] threads = new Thread[16];
        int nThreads = threadGroup.enumerate(threads, true);

        for (int i = 0; i < nThreads; i++) {
            threads[i].interrupt();
        }
    }
}
