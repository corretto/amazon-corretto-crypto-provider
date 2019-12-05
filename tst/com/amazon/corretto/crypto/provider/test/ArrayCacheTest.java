// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReferenceArray;

import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetField;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

// Currently doesn't do any multi-threaded testing. Just general behavior
public class ArrayCacheTest {

    @Test
    public void emptyReturnsNewArray() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, 16);

        for (int size = 1; size <= maxArraySize; size++) {
            byte[] result = cache.getArray(size);
            assertValid(size, result);
            byte[] other = cache.getArray(size);
            assertValid(size, other);

            assertNotSame(result, other);
        }
    }

    @Test
    public void zeroArrayAlwaysSame() {
        final SneakyCache cache = new SneakyCache(127, 16, 16);

        byte[] result = cache.getArray(0);
        assertValid(0, result);
        byte[] other = cache.getArray(0);
        assertSame(result, other);
    }

    @Test
    public void zeroCloneReturnsOriginal() {
        final SneakyCache cache = new SneakyCache(127, 16, 16);

        byte[] result = cache.getArray(0);
        assertValid(0, result);
        byte[] clone = cache.clone(result);
        assertSame(result, clone);

        byte[] newZero = new byte[0];
        clone = cache.clone(newZero);
        assertSame(newZero, clone);
    }

    @Test
    public void overlargeReturnsNew() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, maxArraySize);

        byte[] result = cache.getArray(maxArraySize + 1);
        assertValid(maxArraySize + 1, result);
        byte[] other = cache.getArray(maxArraySize + 1);
        assertValid(maxArraySize + 1, other);
        assertNotSame(result, other);
    }

    @Test
    public void offerOverlargeDoesNotFail() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, maxArraySize);

        byte[] largeArray = new byte[maxArraySize + 1];
        cache.offerArray(largeArray);
    }

    @Test
    public void putOnFullSucceeds() {
        final int arraySize = 1;
        final SneakyCache cache = new SneakyCache(127, 16, arraySize);
        AtomicReferenceArray<byte[]> cachedArrays = cache.getCaches()[arraySize];
        // Fill the cache
        for (int x = 0; x < cachedArrays.length(); x++) {
            cachedArrays.set(x, new byte[arraySize]);
        }

        cache.offerArray(new byte[arraySize]);
    }

    @Test
    public void putRetrieveUsesCache() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, maxArraySize);

        final byte[] result1 = cache.getArray(maxArraySize);
        assertValid(maxArraySize, result1);
        cache.offerArray(result1);
        final byte[] result2 = cache.getArray(maxArraySize);
        assertSame(result1, result2);
    }

    @Test
    public void cloneWorks() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, maxArraySize);
        final SecureRandom rnd = new SecureRandom();

        // We do this to catch if the cache incorrectly modifies arrays passed into clone.
        // By comparing against a master copy which we keep separate, we can detect this.
        final byte[] masterExpected = new byte[maxArraySize];
        rnd.nextBytes(masterExpected);
        final byte[] cloneSrc = masterExpected.clone();

        // First case is a new array
        final byte[] result1 = cache.clone(cloneSrc);
        assertNotSame(cloneSrc, result1);
        assertArrayEquals(masterExpected, cloneSrc);
        assertArrayEquals(masterExpected, result1);

        // Return result1 which should zero it
        cache.offerArray(result1);
        // Checks to ensure it has been zeroed
        assertValid(masterExpected.length, result1);

        // This should be result1 reused
        final byte[] result2 = cache.clone(cloneSrc);
        assertNotSame(cloneSrc, result2);
        assertSame(result1, result2);
        assertArrayEquals(masterExpected, cloneSrc);
        assertArrayEquals(masterExpected, result2);
    }

    @Test
    public void cloneOverLarge() {
        final int maxArraySize = 16;
        final SneakyCache cache = new SneakyCache(127, 16, maxArraySize);
        final SecureRandom rnd = new SecureRandom();

        // We do this to catch if the cache incorrectly modifies arrays passed into clone.
        // By comparing against a master copy which we keep separate, we can detect this.
        final byte[] masterExpected = new byte[maxArraySize + 1];
        rnd.nextBytes(masterExpected);
        final byte[] cloneSrc = masterExpected.clone();

        final byte[] result1 = cache.clone(cloneSrc);
        assertNotSame(cloneSrc, result1);
        assertArrayEquals(masterExpected, cloneSrc);
        assertArrayEquals(masterExpected, result1);
    }

    private static void assertValid(int length, byte[] array) {
        assertEquals(length, array.length);
        for (int x = 0; x < length; x++) {
            assertEquals("Non-zero byte at index " + x, (byte) 0, array[x]);
        }
    }

    @SuppressWarnings({"rawtypes", "unused"})
    private static class SneakyCache {
        private final Object delegate;

        SneakyCache(int cacheSize, int cacheStepLimit, int maxArraySize) {
            try {
                delegate = sneakyConstruct("com.amazon.corretto.crypto.provider.ArrayCache",
                        cacheSize, cacheStepLimit, maxArraySize);
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        byte[] getArray(int length) {
            try {
                return sneakyInvoke(delegate, "getArray", length);
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        byte[] clone(final byte[] array) {
            try {
                return sneakyInvoke(delegate, "clone", array);
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        void offerArray(final byte[] array) {
            try {
                sneakyInvoke(delegate, "offerArray", array);
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        int getLocation() {
            try {
                ThreadLocal tl = sneakyGetField(delegate, "threadState");
                Object state = tl.get();
                return sneakyGetField(state, "location");
            } catch (final Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        int getStepSize() {
            try {
                ThreadLocal tl = sneakyGetField(delegate, "threadState");
                Object state = tl.get();
                return sneakyGetField(state, "stepSize");
            } catch (final Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        AtomicReferenceArray<byte[]>[] getCaches() {
            try {
                return sneakyGetField(delegate, "caches");
            } catch (final Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }
    }
}
