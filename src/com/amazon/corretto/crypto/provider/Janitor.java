// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This class implements an alternative to traditional finalizers, which allows finalizable references to be cancelled
 * if cleanup happens synchronously.
 * <br/>
 * Typical usage will create one long-lived Janitor which will serve for the lifetime of the process, and clean up any
 * Messes which aren't explicitly cleaned before being unreferenced.
 * <br/>
 * In specialized use cases, the Janitor instance itself can be unreferenced; the background cleanup thread will then
 * terminate when all associated Messes are cleaned (and the GC notices the loss of the Janitor reference).
 * <br/>
 * The function of this class is similar to Java 9's {@link java.lang.ref.Cleaner}, but it avoids a single lock on the
 * data structure responsible for keeping the phantom references alive (and is compatible with Java 8).
 */
class Janitor {
    // Every CLEAN_INTERVAL refs we create on a particular shard, we'll check the reference queue for uncleaned entries
    private static final int CLEAN_INTERVAL = 32;
    // When we check the reference queue, we'll process up to CLEAN_BATCH_SIZE entries
    private static final int CLEAN_BATCH_SIZE = 128;
    // Time (in ms) to wait on a single ref queue before rechecking the others
    private static final long CLEAN_TIMEOUT = 1000;

    // Overriding this property directly sets the number of stripes to allocate
    private static final String PROP_NSTRIPES = "janitor.stripes";
    // By default we apply a multiplier to the number of CPUs
    private static final int DEFAULT_PROCESSOR_MULTIPLER = 4; // 4 stripes per CPU (rounded up to a power of two)

    private final JanitorState state;

    Janitor() {
        state = new JanitorState(this);
    }

    Janitor(ThreadFactory factory) {
        state = new JanitorState(this, factory);
    }

    Mess register(Object referent, Runnable cleaner) {
        return state.register(referent, cleaner);
    }

    /**
     * For testing only. Immediately awakens the cleaner thread, which will examine all reference queues for garbage
     * to process. This is not guaranteed to find any garbage, of course; normally, one would want to run this in a loop
     * with a sleep for some time in the hopes that reference processing will catch up.
     */
    void wake() {
        state.cleaner.interrupt();
    }

    /**
     * For testing only. Returns the stripe count for this janitor.
     */
    int getStripeCount() {
        return state.stripes.length;
    }

    /**
     * Represents a pending cleanup action tracked by a Janitor. By invoking clean() on a Mess, the cleanup action will
     * execute immediately, and the overhead for tracking the pending cleanup can be avoided.
     *
     * It is not necessary to keep a reference to the Mess if explicit cleanup is not necessary (or possible); the
     * Janitor will ensure that the cleanup action is invoked when the associated reference is collected regardless
     * of whether the Mess object is reachable.
     */
    interface Mess {
        /**
         * Invokes the cleanup action associated with this Mess. This method is idempotent and thread-safe; the cleanup
         * action will only be invoked once. If multiple invocations occur in parallel, however, it is not guaranteed
         * that the cleanup action will be complete before returning; duplicate invocations may result in an immediate
         * return without waiting for the cleanup to complete.
         */
        void clean();
    }

    /**
     * The actual implementation of the Mess. Each HeldReference is a weak reference to the referent associated with the
     * cleanup action. We use WeakReferences instead of phantom references as phantom references keep their referent
     * alive (but inaccessible) until the phantom reference is explicitly cleared or becomes dead; we don't need that
     * behavior, so we use a weak reference to allow the GC to clear the referent pointer implicitly.
     *
     * HeldReferences need to remain strongly reachable until their cleanup action is executed. To accomplish this, we
     * maintain a circular (intrusive) doubly linked list through held references. Each Stripe is associated with one
     * such list, and manipulation of the list is protected by the Stripe object monitor.
     */
    private static final class HeldReference extends WeakReference<Object> implements Mess {
        // TODO: Use VarHandle when we no longer need to support Java 8
        private static final AtomicReferenceFieldUpdater<HeldReference, Runnable> F_CLEANER
                = AtomicReferenceFieldUpdater.newUpdater(HeldReference.class, Runnable.class, "cleaner");

        private final Stripe owningStripe;

        //@GuardedBy("owningStripe") // Restore once replacement for JSR-305 available
        private HeldReference prev, next;

        @SuppressWarnings("unused") // accessed reflectively via F_CLEANER
        private volatile Runnable cleaner;

        HeldReference(final Object referent, final Stripe owningStripe, Runnable cleaner) {
            super(referent, owningStripe.queue);
            this.owningStripe = owningStripe;
            this.cleaner = cleaner;
        }

        @Override
        public final void clean() {
            // Swap the cleaner with null. The idea here is to ensure we invoke the cleaner only once but avoid taking
            // an additional lock to protect the cleanup action.

            Runnable cleaner = F_CLEANER.getAndSet(this, null);

            if (cleaner == null) {
                return;
            }

            try {
                cleaner.run();
            } catch (Throwable t) {
                // We ignore all exceptions, even Errors. This is because an Error leaked from the user cleanup callback
                // would otherwise result in the cleaner thread as a whole dying, resulting in a permanent memory leak.
                // If the user cleaner fails there isn't much we can do about it anyway.

                // This behavior is consistent with the behavior of ordinary finalizers. The JDK 9 cleaner chooses a
                // different approach - uncaught throwables result in the VM being terminated.
            }

            // Remove the underlying reference to the referent. This isn't strictly necessary, but it means the GC
            // doesn't have to keep the referent alive until reference processing completes (if the reference has not
            // yet been found dead).
            clear();

            synchronized (owningStripe) {
                owningStripe.outstandingRefs--;

                next.prev = prev;
                prev.next = next;
                next = prev = this;
            }
        }
    }

    /**
     * We organize our reference lists and reference queues into a number of "stripes"; each Java thread is permanently
     * and randomly bound to one of the Stripes, and any messes it creates are assigned to this stripe. This helps avoid
     * contention between multiple threads when creating messes or processing the mess reference queues.
     */
    private static final class Stripe {
        private static final AtomicIntegerFieldUpdater<Stripe> F_OBJS_CREATED_SINCE =
                AtomicIntegerFieldUpdater.newUpdater(Stripe.class, "objectsCreatedSinceLastClean");

        private final ReferenceQueue<Object> queue = new ReferenceQueue<>();

        // We hold our own lock around the reference queue to avoid blocking on the implicit internal queue lock when
        // performing opportunistic cleanup.
        private final ReentrantLock queueLock = new ReentrantLock();

        // The head element of the doubly-linked list of references. This reference will never be enqueued and thus
        // will remain in the list indefinitely.
        private final HeldReference head;

        // The number of objects that have been created since the last attempted synchronous cleanup.
        @SuppressWarnings("unused") // accessed reflectively via F_OBJS_CREATED_SINCE
        private volatile int objectsCreatedSinceLastClean = 0;

        // The number of outstanding references, not including the head element.
        private long outstandingRefs = 0;

        Stripe() {
            // The head reference uses the queue itself as its referent to ensure that it will never be enqueued.
            this.head = new HeldReference(queue, this, () -> {});
            this.head.prev = this.head.next =  this.head;
        }

        synchronized boolean hasOutstandingRefs() {
            return outstandingRefs != 0;
        }

        Mess add(Object referent, Runnable cleaner) {
            // n = (n + 1) % CLEAN_INTERVAL; check for rollover
            // We avoid holding the lock to ensure we don't have any sort of lock inversion issue, or deadlocks caused
            // by user cleaner code doing who-knows-what.
            if (F_OBJS_CREATED_SINCE.updateAndGet(this, n -> n >= CLEAN_INTERVAL - 1 ? 0 : n + 1) == 0) {
                tryClean(false);
            }

            synchronized (this) {
                // It is essential that we take the monitor _before_ creating this reference. Once we create this
                // reference, it's very possible that referent no longer has any strong references, and is immediately
                // eligible to be enqueued. Since we haven't finished setting up the DLL yet, this means the node could
                // be removed from the list before it is added - thus becoming stuck in the doubly linked list forever.
                //
                // Holding the monitor means that, even if this were to occur, the cleaner thread will be stuck waiting
                // for the monitor (in HeldReference.clean()), and by the time it's released, we'll have finished
                // establishing the doubly linked list.
                HeldReference ref = new HeldReference(referent, this, cleaner);

                outstandingRefs++;

                ref.prev = head;
                ref.next = head.next;
                ref.next.prev = ref;
                ref.prev.next = ref;

                return ref;
            }
        }

        /**
         * Cleans up to CLEAN_BATCH_SIZE objects.
         *
         * @param block True to block for CLEAN_WAIT_INTERVAL until objects are available to clean
         * @return The number of objects cleaned
         */
        private int tryClean(boolean block) {
            if (block) {
                queueLock.lock();
            } else {
                if (!queueLock.tryLock()) {
                    return 0;
                }
            }

            try {
                for (int i = 0; i < CLEAN_BATCH_SIZE; i++) {
                    HeldReference ref;
                    try {
                        ref = (HeldReference) (block ? queue.remove(CLEAN_TIMEOUT) : queue.poll());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return i;
                    }

                    if (ref == null) {
                        return i;
                    }

                    ref.clean();

                    // Only block on the first reference
                    block = false;
                }

                return CLEAN_BATCH_SIZE;
            } finally {
                queueLock.unlock();
            }
        }
    }

    private static final class JanitorState {
        private final int stripeIndexMask;
        private final Stripe[] stripes;
        private final Thread cleaner;

        JanitorState(Janitor parent) {
            this(parent, task -> {
                Thread cleaner = new Thread(task);

                cleaner.setDaemon(true);
                cleaner.setName("Native reference cleanup thread");
                cleaner.setPriority(Thread.MAX_PRIORITY - 2); // same as the thread priority for the Java 9 Cleaner thread
                return cleaner;
            });
        }

        JanitorState(Janitor parent, ThreadFactory factory) {
            int nstripes;

            if (Loader.getProperty(PROP_NSTRIPES) != null) {
                nstripes = Integer.parseInt(Loader.getProperty(PROP_NSTRIPES));
            } else {
                nstripes = Runtime.getRuntime().availableProcessors() * DEFAULT_PROCESSOR_MULTIPLER;
            }

            if (nstripes <= 0) {
                throw new IllegalArgumentException("Bad value for " + PROP_NSTRIPES + " property; must be positive");
            }

            // Round nstripes up to a power of two
            // To do this, we note that we can almost achieve this by clearing all but the top bit. This will leave
            // a power of two unchanged, and everything else will be rounded _down_ to a power of two.
            // To avoid rounding down, we can then multiply by two, but this means that numbers that are already
            // a power of two are now doubled - and to fix this, we subtract one at the start.

            // Note that this does not work with an input of 1, so we'll hardcode a minimum of 1.
            nstripes = Math.max(1, 2 * Integer.highestOneBit(nstripes - 1));

            stripes = new Stripe[nstripes];

            // This mask is ANDed with thread hash codes to obtain the stripe index for that thread. This is equivalent
            // to computing modulo stripes.length, assuming stripes.length is a power of 2.
            stripeIndexMask = stripes.length - 1;

            for (int i = 0; i < stripes.length; i++) {
                stripes[i] = new Stripe();
            }

            // This reference keeps the cleaner thread alive - it will terminate when zero outstanding refs remain, so
            // by keeping a reference around watching the outer Janitor, we ensure that when all outstanding registered
            // refs are gone AND the Janitor is dead (thus, no new refs can be created), we'll terminate the cleanup
            // thread.

            // We don't need an explicit cleanup action here, it's enough that it implicitly updates the outstandingRefs
            // counters.
            stripes[0].add(parent, () -> {});

            cleaner = factory.newThread(this::cleanerThread);
            cleaner.start();
        }

        private void cleanerThread() {
            int sleepIndex = 0;

            while (true) {
                boolean cleanedSomeRefs = false;
                boolean outstandingRefsRemain = false;

                // First, we'll clean some refs from every stripe, without blocking.
                for (int i = 0; i < stripes.length; i++) {
                    if (stripes[i].tryClean(false) > 0) {
                        cleanedSomeRefs = true;
                    }

                    outstandingRefsRemain = outstandingRefsRemain || stripes[i].hasOutstandingRefs();
                }

                if (cleanedSomeRefs) {
                    // Don't sleep unless we run out of refs to process on all stripes.
                    continue;
                }

                if (!outstandingRefsRemain) {
                    // We've drained all refs, which means the Janitor is also gone and our work is done.
                    return;
                }

                // Go to sleep on an arbitrary stripe. If we don't end up finding anything on this stripe, move on to
                // the next stripe on the next iteration (if there's only one thread generating garbage we hope to end
                // up stuck on that thread).
                if (stripes[sleepIndex].tryClean(true) == 0) {
                    sleepIndex = (sleepIndex + 1) & stripeIndexMask;
                }

                // We use the thread interrupt to wake the thread from its slumber to make unit tests more reproducible.
                // Now that we're awake we can clear the interrupt flag.
                Thread.interrupted();
            }
        }

        private Stripe getStripe() {
            return stripes[System.identityHashCode(Thread.currentThread()) & stripeIndexMask];
        }

        Mess register(Object referent, Runnable cleanup) {
            return getStripe().add(referent, cleanup);
        }
    }

}
