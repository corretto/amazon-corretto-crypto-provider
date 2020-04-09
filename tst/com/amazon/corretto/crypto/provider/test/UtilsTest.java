// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;

import org.junit.AssumptionViolatedException;
import org.junit.Before;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;


public class UtilsTest {
    private static final Class<?> UTILS_CLASS;

    static {
        try {
            UTILS_CLASS = Class.forName("com.amazon.corretto.crypto.provider.Utils");
        } catch (final ClassNotFoundException ex) {
            throw new AssertionError(ex); 
        }
    }

    boolean maybeOverlaps(ByteBuffer a, ByteBuffer b) throws Throwable {
        return (Boolean) sneakyInvoke(UTILS_CLASS, "buffersMaybeOverlap", a, b);
    }

    private void assertMaybeOverlaps0(ByteBuffer a, ByteBuffer b) throws Throwable {
        assertTrue(maybeOverlaps(a, b));
        assertTrue(maybeOverlaps(b, a));
    }

    private void assertMaybeOverlaps(ByteBuffer a, ByteBuffer b) throws Throwable {
        assertMaybeOverlaps0(a, b);
        assertMaybeOverlaps0(a.slice(), b);
        assertMaybeOverlaps0(a, b.slice());
        assertMaybeOverlaps0(a.slice(), b.slice());
    }

    private void assertNoOverlap0(ByteBuffer a, ByteBuffer b) throws Throwable {
        assertFalse(maybeOverlaps(a, b));
        assertFalse(maybeOverlaps(b, a));
    }

    private void assertNoOverlap(ByteBuffer a, ByteBuffer b) throws Throwable {
        assertNoOverlap0(a, b);
        assertNoOverlap0(a.slice(), b);
        assertNoOverlap0(a, b.slice());
        assertNoOverlap0(a.slice(), b.slice());
    }

    boolean arraysOverlap(byte[] a1, int o1, byte[] a2, int o2, int length) throws Throwable {
        return (Boolean) sneakyInvoke(UTILS_CLASS, "arraysOverlap", a1, o1, a2, o2, length);
    }

    @Before
    public void setUp() throws Exception {
        // Touch AmazonCorrettoCryptoProvider to get the JNI library loaded
        assertNotNull(AmazonCorrettoCryptoProvider.INSTANCE);
    }

    @Test
    public void whenArrayBuffersAreDifferentArrays_noOverlap() throws Throwable {
        ByteBuffer a = ByteBuffer.allocate(100);
        ByteBuffer b = ByteBuffer.allocate(100);

        assertNoOverlap(a, b);

        b.position(10);
        a.limit(11);

        assertNoOverlap(a, b);
    }

    @Test
    public void whenArrayBuffersAreDifferentArrays_correctOverlap() throws Throwable {
        ByteBuffer a = ByteBuffer.allocate(100);
        ByteBuffer b = a.duplicate();

        assertMaybeOverlaps(a, b);

        b.limit(10);

        assertMaybeOverlaps(a, b);

        b.position(10);

        assertMaybeOverlaps(a, b);

        a.limit(11);

        assertMaybeOverlaps(a, b);

        a.limit(10);

        assertNoOverlap(a, b);
    }

    @Test
    public void whenOneBufferIsReadOnly_assumesOverlap() throws Throwable {
        ByteBuffer a = ByteBuffer.allocate(100);
        ByteBuffer b = ByteBuffer.allocate(100).asReadOnlyBuffer();

        assertMaybeOverlaps(a, b);
    }

    @Test
    public void whenOneBufferIsDirect_noOverlap() throws Throwable {
        ByteBuffer a = ByteBuffer.allocate(100);
        ByteBuffer b = ByteBuffer.allocateDirect(100);

        assertNoOverlap(a, b);
        assertNoOverlap(a.asReadOnlyBuffer(), b);
    }

    @Test
    public void whenBothBuffersAreDirect_fromDifferentAllocations_noOverlap() throws Throwable {
        ByteBuffer a = ByteBuffer.allocateDirect(100);
        ByteBuffer b = ByteBuffer.allocateDirect(100);

        assertNoOverlap(a, b);
    }

    @Test
    public void whenMaximumSizeNativeBuffersAreUsed_correctOverlapDetermination() throws Throwable {
        ByteBuffer buf;
        try {
            buf = ByteBuffer.allocateDirect(Integer.MAX_VALUE);
        } catch (OutOfMemoryError e) {
            throw new AssumptionViolatedException("Unable to allocate 2GB native buffer", e);
        }

        ByteBuffer a = buf.duplicate();
        ByteBuffer b = buf.duplicate();

        b.position(b.limit() - 1);
        assertMaybeOverlaps(a, b);

        a.limit(1);
        assertNoOverlap(a, b);

        a.limit(a.capacity());
        a.position(b.position());
        assertMaybeOverlaps(a, b);
    }

    @Test
    public void arraysOverlapTests() throws Throwable {
        byte[] arr1 = new byte[10];
        byte[] arr2 = new byte[10];

        assertTrue(arraysOverlap(arr1, 0, arr1, 0, 10));
        assertFalse(arraysOverlap(arr1, 0, arr2, 0, 10));

        assertTrue(arraysOverlap(arr1, 0, arr1, 5, 10));
        assertTrue(arraysOverlap(arr1, 0, arr1, 5, 6));
        assertFalse(arraysOverlap(arr1, 0, arr1, 5, 5));
        assertTrue(arraysOverlap(arr1, 1, arr1, 5, 5));
        assertTrue(arraysOverlap(arr1, 5, arr1, 0, 10));
        assertTrue(arraysOverlap(arr1, 5, arr1, 0, 6));
        assertFalse(arraysOverlap(arr1, 5, arr1, 0, 5));
        assertTrue(arraysOverlap(arr1, 5, arr1, 1, 5));
    }
}

