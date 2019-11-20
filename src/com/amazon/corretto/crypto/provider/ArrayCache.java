package com.amazon.corretto.crypto.provider;

import java.util.Arrays;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerArray;

/**
 * Caches instances of {@code byte[]} for re-use.
 *
 * The maximum data cached is {@code arrayCacheSize * 512}KB.
 * By default this is 256MB.
 */
class ArrayCache {
    private static final int CACHE_SIZE = Integer.parseInt(Loader.getProperty("arrayCacheSize", "512"));
    private static final int MAX_ARRAY_SIZE = 1024;
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static final ConcurrentLinkedQueue<byte[]>[] QUEUES =
            (ConcurrentLinkedQueue<byte[]>[]) new ConcurrentLinkedQueue[MAX_ARRAY_SIZE + 1];
    private static AtomicIntegerArray QUEUE_SIZES = new AtomicIntegerArray(QUEUES.length);

    private static AtomicIntegerArray TMP = new AtomicIntegerArray(QUEUES.length);

    static {
        for (int x = 1; x < QUEUES.length; x++) {
            QUEUES[x] = new ConcurrentLinkedQueue<>();
        }
    }

    public static byte[] getArray(int length) {
        if (length == 0) {
            return Utils.EMPTY_ARRAY;
        }
        if (length > MAX_ARRAY_SIZE) {
            return new byte[length];
        }
        final ConcurrentLinkedQueue<byte[]> queue = QUEUES[length];

        final byte[] result = queue.poll();
        if (result == null) {
            // The cache is empty
            return new byte[length];
        }

        // Decrement our counter
        QUEUE_SIZES.decrementAndGet(length);

        // Return the cached item
        return result;
    }

    public static byte[] clone(final byte[] array) {
        final byte[] result = getArray(array.length);
        if (result != null) {
            System.arraycopy(array, 0, result, 0, array.length);
            return result;
        } else {
            return array.clone();
        }
    }

    public static void offerArray(final byte[] array) {
        final int length = array.length;
        if (length == 0) {
            return;
        }

        if (length > MAX_ARRAY_SIZE) {
            return;
        }

        final ConcurrentLinkedQueue<byte[]> queue = QUEUES[length];

        if (QUEUE_SIZES.get(length) > CACHE_SIZE) {
            // We have enough already, so drop it
            return;
        }

        // Wipe any potentially sensitive data
        Arrays.fill(array, (byte) 0);

        // Increment our count
        // Yes, in a highly contested case we may end up with more than the max. That's okay.
        QUEUE_SIZES.incrementAndGet(length);

        // Save the array for reuse
        queue.add(array);
    }
}
