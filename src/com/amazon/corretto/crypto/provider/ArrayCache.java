// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * Caches instances of {@code byte[]} for re-use. <em>It is critically important that arrays are no longer used
 * or referenced after being passed to {@link #offerArray(byte[])}.</em>
 *
 * <p>With the <em>exception of zero-length-arrays</em> this acts equivalently to creating and discarding new arrays each-time.
 * Zero-length arrays may be deduped. This is safe provided you don't use it for locking or other
 * identity equality operations.</p>
 *
 * <p>The current implementation of this is a lock-free concurrent data-structure based on a number of instances of
 * {@link AtomicReferenceArray} (one per byte-array size), each of <em>prime</em> size
 * {@link #cacheSize} (currently 127).
 * These atomic-arrays each start empty.
 * The first time a thread attempts to access this cache a random {@code stepSize} and {@code location} are created and
 * stored in a {@link ThreadLocal}.</p>
 *
 * <p>When an array is requested with {@link #getArray(int)} (assuming it is a cached size), the appropriate
 * {@link AtomicReferenceArray} is searched (starting at the thread-specific {@code location} and iterating forward over
 * it with increments of {@code stepSize}. At each index the cache performs an atomic-swap, retrieving the value
 * at the location and atomically setting that array entry to {@code null}.
 * If a non-null array is found, it is returned and the search terminates (updating the thread-specific {@code location}).
 * If a null element is found, this search repeats {@link #cacheStepLimit} times.
 * If the search fails (or this is an uncached size), a new array is returned.</p>
 *
 * <p>When an array is offered to the cache with {@link #offerArray(byte[])}e), the appropriate
 * {@link AtomicReferenceArray} is searched (starting at the thread-specific {@code location} and iterating backward over
 * it with increments of {@code stepSize}. At each location an atomic compare-and-set (CAS) is used to store the
 * byte array if-and-only-if the current value at that index is {@code null}. This is repeated until it is
 * successfully stored or no open slots are found in {@link #cacheStepLimit} attempts.
 * If no open slots are found, then the offered array is just dropped.</p>
 *
 * <p>The maximum data cached is {@code arrayCacheSize * 512}KB.
 * By default this is 63.5MB</p>
 */
class ArrayCache {
    // This must be a prime number.
    private static final int CACHE_SIZE = Integer.parseInt(Loader.getProperty("arrayCacheSize", "127"));
    private static final int CACHE_STEP_LIMIT = Integer.parseInt(Loader.getProperty("arrayCacheStepLimit", "16"));
    private static final int MAX_ARRAY_SIZE = 1024;

    public static final ArrayCache INSTANCE = new ArrayCache(CACHE_SIZE, CACHE_STEP_LIMIT, MAX_ARRAY_SIZE);

    private static final class ThreadState {
        public final int stepSize;
        public int location;

        private ThreadState() {
            // These numbers do not need to be securely random
            final ThreadLocalRandom insecureRandom = ThreadLocalRandom.current();
            stepSize = insecureRandom.nextInt(1, CACHE_SIZE); // Avoid 0 case
            location = insecureRandom.nextInt(0, CACHE_SIZE);
        }
    }

    private final ThreadLocal<ThreadState> threadState;
    private final int cacheSize;
    private final int cacheStepLimit;
    private final int maxArraySize;
    private final AtomicReferenceArray<byte[]>[] caches;

    @SuppressWarnings({"unchecked", "rawtypes"})
    private ArrayCache(int cacheSize, int cacheStepLimit, int maxArraySize) {
        this.cacheSize = cacheSize;
        this.cacheStepLimit = cacheStepLimit;
        this.maxArraySize = maxArraySize;

        threadState = ThreadLocal.withInitial(ThreadState::new);
        caches = (AtomicReferenceArray<byte[]>[]) new AtomicReferenceArray[maxArraySize + 1];
        for (int x = 1; x < caches.length; x++) {
            caches[x] = new AtomicReferenceArray<>(this.cacheSize);
        }
    }

    /**
     * Returns an array of size {@code length}.
     * This acts identically (from a caller perspective) to simply calling {@code new byte[length]}.
     *
     * @param length size of the array to return
     * @return array
     */
    byte[] getArray(int length) {
        if (length == 0) {
            return Utils.EMPTY_ARRAY;
        }
        if (length > maxArraySize) {
            return new byte[length];
        }
        final ThreadState state = threadState.get();
        final int stepSize = state.stepSize;
        int location = state.location;

        final AtomicReferenceArray<byte[]> cache = caches[length];
        for (int x = 0; x < cacheStepLimit; x++) {
            final byte[] candidate = cache.getAndSet(location, null);
            if (candidate != null) {
                state.location = location;
                return candidate;
            }
            location = (stepSize + location) % cacheSize;
        }

        // Nothing found, create a new one and return
        return new byte[length];
    }

    /**
     * Returns a copy of {@code array}.
     * This acts identically (from a caller perspective) to simply calling
     * {@code array.length == 0 ? array : array.clone}.
     * As zero-length arrays will not be copied they may not be safely used for locking.
     *
     * @param array to be cloned
     * @return clone
     */
    byte[] clone(final byte[] array) {
        if (array.length == 0) {
            return array;
        }
        final byte[] result = getArray(array.length);
        System.arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    /**
     * Offers {@code array} for re-use by the cache.
     * <em>After this method is called {@code array} <em>MUST NOT</em> be used for anything and
     * ideally will no longer be reachable either through being set to {@code null} or going out of scope.</em>
     *
     * @param array to be returned to the cache
     */
    // AtomicReferenceArray.weakCompareAndSet has the correct behavior and is present in Java 8.
    // Java9+ deprecates it in favor of weakCompareAndSetPlain (to avoid naming confusion).
    @SuppressWarnings("deprecation")
    void offerArray(final byte[] array) {
        final int length = array.length;
        if (length == 0) {
            return;
        }

        if (length > maxArraySize) {
            return;
        }

        Arrays.fill(array, (byte) 0); // This must come before we potentially store it to avoid concurrency issues.

        final AtomicReferenceArray<byte[]> cache = caches[length];
        final ThreadState state = threadState.get();
        final int stepSize = state.stepSize;

        int location = state.location;
        for (int x = 0; x < cacheStepLimit; x++) {
            if (cache.weakCompareAndSet(location, null, array)) {
                state.location = location;
                return;
            }
            location = (stepSize - location) % cacheSize;
            if (location < 0) {
                location += cacheSize;
            }
        }
    }
}
