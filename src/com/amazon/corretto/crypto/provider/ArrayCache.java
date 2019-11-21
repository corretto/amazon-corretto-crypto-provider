package com.amazon.corretto.crypto.provider;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * Caches instances of {@code byte[]} for re-use.
 *
 * The maximum data cached is {@code arrayCacheSize * 512}KB.
 * By default this is 256MB.
 */
class ArrayCache {
    private static final int STEP_SIZE = 17;
    private static final int CACHE_SIZE = Integer.parseInt(Loader.getProperty("arrayCacheSize", "128"));
    private static final int CACHE_STEP_LIMIT = Integer.parseInt(Loader.getProperty("arrayCacheStepLimit", "16"));
    private static final int MAX_ARRAY_SIZE = 1024;
    private static final ThreadLocal<Integer> START_INDEX = new ThreadLocal<Integer>() {
        @Override
        protected Integer initialValue() {
            return Long.hashCode(Thread.currentThread().getId()) % CACHE_SIZE;
        }
    };
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static final AtomicReferenceArray<byte[]>[] QUEUES =
            (AtomicReferenceArray<byte[]>[]) new AtomicReferenceArray[MAX_ARRAY_SIZE + 1];

    static {
        for (int x = 1; x < QUEUES.length; x++) {
            QUEUES[x] = new AtomicReferenceArray<>(CACHE_SIZE);
        }
    }

    public static byte[] getArray(int length) {
        if (length == 0) {
            return Utils.EMPTY_ARRAY;
        }
        if (length > MAX_ARRAY_SIZE) {
            return new byte[length];
        }
        int startIndex = START_INDEX.get();

        final AtomicReferenceArray<byte[]> queue = QUEUES[length];
        for (int x = 0; x < CACHE_STEP_LIMIT; x++) {
            final byte[] candidate = queue.getAndSet(startIndex, null);
            if (candidate != null) {
                START_INDEX.set(startIndex);
                return candidate;
            }
            startIndex = (STEP_SIZE + startIndex) % CACHE_SIZE;
        }

        // Nothing found, create a new one and return
        return new byte[length];
    }

    public static byte[] clone(final byte[] array) {
        if (array.length == 0) {
            return Utils.EMPTY_ARRAY;
        }
        final byte[] result = getArray(array.length);
        if (result != null) {
            System.arraycopy(array, 0, result, 0, array.length);
            return result;
        } else {
            return array.clone();
        }
    }

    @SuppressWarnings("deprecation")
    public static void offerArray(final byte[] array) {
        final int length = array.length;
        if (length == 0) {
            return;
        }

        if (length > MAX_ARRAY_SIZE) {
            return;
        }

        int startIndex = START_INDEX.get();

        Arrays.fill(array, (byte) 0); // This must come before we potentially store it
        final AtomicReferenceArray<byte[]> queue = QUEUES[length];
        for (int x = 0; x < CACHE_STEP_LIMIT; x++) {
            // TODO: Verify that this is the correct method
            if (queue.weakCompareAndSet(startIndex, null, array)) {
                START_INDEX.set(startIndex);
                return;
            }
            startIndex = (STEP_SIZE - startIndex) % CACHE_SIZE;
            if (startIndex < 0) {
                startIndex += CACHE_SIZE;
            }
        }
    }
}
