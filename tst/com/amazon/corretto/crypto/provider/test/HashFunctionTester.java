// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class HashFunctionTester {
    private static final Class<?> UTILS_CLASS;
    String algorithm;
    MessageDigest jceDigest;
    MessageDigest amzDigest;

    static {
        try {
            UTILS_CLASS = Class.forName("com.amazon.corretto.crypto.provider.Utils");
        } catch (final ClassNotFoundException ex) {
            throw new AssertionError(ex);
        }
    }

    public HashFunctionTester(String algorithm) {
        this.algorithm = algorithm;
    }

    public void test(Iterator<RspTestEntry> tests) throws Throwable {
        amzDigest = getAmazonInstance();
        while (tests.hasNext()) {
            final RspTestEntry entry = tests.next();
            final byte[] msg = Arrays.copyOf(
                    entry.getInstanceFromHex("Msg"),
                    Integer.parseInt(entry.getInstance("Len")) / 8);
            final byte[] expected = entry.getInstanceFromHex("MD");
            sneakyInvoke(UTILS_CLASS, "testDigest", amzDigest, msg, expected);
        }
    }

    private void test(long seed, int chunkCount) throws Exception {
        Random r = new Random(seed);

        int resetType = r.nextInt(3);
        if (jceDigest == null) resetType = 0;

        switch (resetType) {
            case 0: {
                // Allocate new digest objects
                jceDigest = getDefaultInstance();
                amzDigest = getAmazonInstance();
                break;
            }
            case 1: {
                // Gratuitous reset
                jceDigest.reset();
                amzDigest.reset();
                break;
            }
            case 2: {
                // Do nothing (digest() should have reset us on the last iteration)
                break;
            }
        }

        for (int i = 0; i < chunkCount; i++) {
            int bufferType = r.nextInt(4);
            int bufferLength = r.nextDouble() < 0.1 ? 512*1024+r.nextInt(1024) : r.nextInt(1024);

            ByteBuffer buf = getBuffer(r, bufferType == 0, bufferType != 2 && r.nextBoolean(), bufferLength);

            switch (bufferType) {
                case 0:
                case 1: {
                    ByteBuffer maybeReadOnly = r.nextBoolean() ? buf.asReadOnlyBuffer() : buf;

                    jceDigest.update(maybeReadOnly.duplicate());
                    amzDigest.update(maybeReadOnly);
                    assertEquals(maybeReadOnly.position(), maybeReadOnly.limit());

                    break;
                }
                case 2: {
                    byte[] adata = buf.array();

                    jceDigest.update(adata, buf.position(), buf.remaining());
                    amzDigest.update(adata, buf.position(), buf.remaining());
                    break;
                }
                case 3: {
                    // ignore the buffer and just update with a single byte
                    byte b = (byte)(r.nextInt() & 0xFF);
                    jceDigest.update(b);
                    amzDigest.update(b);
                    break;
                }
            }
        }

        byte[] jceResult, amzResult;
        switch (r.nextInt(4)) {
            case 0: {
                // Complete into existing array
                int offset = r.nextInt(16);
                jceResult = finishDigestIntoExistingArray(jceDigest, offset);
                amzResult = finishDigestIntoExistingArray(amzDigest, offset);
                break;
            }
            case 1: {
                // Complete with single call
                jceResult = jceDigest.digest();
                amzResult = amzDigest.digest();
                break;
            }
            case 2: {
                // Pass additional data
                int buflen = r.nextInt(1024) + (r.nextBoolean() ? 512 * 1024 : 0);
                byte[] buf = new byte[buflen];
                r.nextBytes(buf);

                jceResult = jceDigest.digest(buf);
                amzResult = amzDigest.digest(buf);
                break;
            }
            case 3: {
                // Reset without getting the result (to verify that we reset the state properly for the next test)
                jceResult = amzResult = new byte[0];
                jceDigest.reset();
                amzDigest.reset();
                break;
            }
            default: throw new AssertionError();
        }

        assertArrayEquals(jceResult, amzResult);
    }

    private MessageDigest getAmazonInstance() {
        try {
            return MessageDigest.getInstance(algorithm, TestUtil.NATIVE_PROVIDER);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private MessageDigest getDefaultInstance() {
        try {
            return MessageDigest.getInstance(algorithm, "SUN");
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    public void testRandomly(int iterations) throws Exception {
        Random r = new Random();
        long seed = 0;

        try {
            for (int i = 0; i < iterations; i++) {
                seed = r.nextLong();
                test(seed, 1);
            }

            for (int i = 0; i < iterations; i++) {
                test(seed, 2);
            }
        } catch (Throwable e) {
            throw new AssertionError("Failed with seed " + seed, e);
        }
    }

    private ByteBuffer getBuffer(Random r, boolean isNative, boolean isReadOnly, int bufferLength) {
        int beforePad = r.nextBoolean() ? r.nextInt(1024) : 0;
        int afterPad = r.nextBoolean() ? r.nextInt(1024) : 0;
        int totalSize = beforePad + bufferLength + afterPad;

        ByteBuffer buf = isNative ? ByteBuffer.allocateDirect(totalSize) : ByteBuffer.allocate(totalSize);

        buf.position(beforePad);
        buf.mark();
        buf.limit(beforePad + bufferLength);

        byte[] randBuf = new byte[bufferLength];
        r.nextBytes(randBuf);

        buf.duplicate().put(randBuf);

        return isReadOnly ? buf.asReadOnlyBuffer() : buf;
    }

    private byte[] finishDigestIntoExistingArray(MessageDigest jceDigest, int offset) throws DigestException {
        byte[] result = new byte[jceDigest.getDigestLength()];
        byte[] buf = new byte[offset + jceDigest.getDigestLength()];

        jceDigest.digest(buf, offset, jceDigest.getDigestLength());
        System.arraycopy(buf, offset, result, 0, result.length);

        return result;
    }

    public void testAPI() throws Exception {
        MessageDigest md = getAmazonInstance();

        // Make sure we're testing the right spi
        assertTrue(AmazonCorrettoCryptoProvider.class.isAssignableFrom(md.getProvider().getClass()));

        testBoundsChecks();
        testByteBufferReflectionFallback();
        testClone();
        testDirectBufferSlices();
        testLargeArray();
        testLargeDirectBuffer();
    }

    private void testLargeArray() {
        MessageDigest amzn = getAmazonInstance();
        MessageDigest jce = getDefaultInstance();

        byte[] data = new byte[4096];
        amzn.update(data);
        jce.update(data);

        assertArrayEquals(jce.digest(), amzn.digest());
    }

    private void testLargeDirectBuffer() {
        MessageDigest amzn = getAmazonInstance();
        MessageDigest jce = getDefaultInstance();

        ByteBuffer data = ByteBuffer.allocateDirect(4096);
        amzn.update(data.duplicate());
        jce.update(data.duplicate());

        assertArrayEquals(jce.digest(), amzn.digest());
    }

    private void testDirectBufferSlices() {

        ByteBuffer nativeBuf = ByteBuffer.allocateDirect(4);
        nativeBuf.put(new byte[] { 1, 2, 3, 4 });

        nativeBuf.position(1);
        nativeBuf.limit(3);

        MessageDigest md = getAmazonInstance();
        MessageDigest expected = getDefaultInstance();

        md.update(nativeBuf.duplicate());
        expected.update(nativeBuf.duplicate());

        assertArrayEquals(expected.digest(), md.digest());
    }

    private void testClone() throws CloneNotSupportedException {
        MessageDigest md = getAmazonInstance();

        md.update(new byte[] { 1, 2, 3 });

        MessageDigest md2 = (MessageDigest) md.clone();

        md2.update(new byte[] { 4, 5, 6 });
        md.update(new byte[] { 7, 8, 9 });

        assertArrayEquals(
            getDefaultInstance().digest(new byte[] { 1,2,3,4,5,6 }),
            md2.digest()
        );
        assertArrayEquals(
            getDefaultInstance().digest(new byte[] { 1,2,3,7,8,9 }),
            md.digest()
        );
    }

    private void testByteBufferReflectionFallback() {
        MessageDigest md = getAmazonInstance();

        // Test fallback for when byte buffer reflection fails
        TestUtil.disableByteBufferReflection();
        md.update(ByteBuffer.allocate(1).asReadOnlyBuffer());
        byte[] digest = md.digest();

        assertArrayEquals(digest, getDefaultInstance().digest(new byte[1]));

        try {
            TestUtil.enableByteBufferReflection();
        } catch (Throwable t) {
            // We're probably building on a newer JDK that changed something under us
        }
    }

    private void testBoundsChecks() throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException {
        MessageDigest md = getAmazonInstance();
        // We'll want to call engine* methods directly to avoid any bounds checks provided by MessageDigest itself
        // First get a Lookup instance that bypasses access checks to allow us to call protected methods.
        Field IMPL_LOOKUP_FIELD = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
        IMPL_LOOKUP_FIELD.setAccessible(true);
        MethodHandles.Lookup LOOKUP = (MethodHandles.Lookup) IMPL_LOOKUP_FIELD.get(null);

        MethodHandle mh_updateArray
            = LOOKUP.findVirtual(md.getClass(), "engineUpdate",
                                 MethodType.methodType(Void.TYPE, byte[].class, Integer.TYPE, Integer.TYPE));
        MethodHandle mh_updateByteBuf
            = LOOKUP.findVirtual(md.getClass(), "engineUpdate",
                                 MethodType.methodType(Void.TYPE, ByteBuffer.class));
        MethodHandle mh_engineDigest
            = LOOKUP.findVirtual(md.getClass(), "engineDigest",
                                 MethodType.methodType(Integer.TYPE, byte[].class, Integer.TYPE, Integer.TYPE));

        // Buffer overrun tests
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     () -> mh_updateArray.invoke(md, new byte[1], 2, 1));
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     () -> mh_updateArray.invoke(md, new byte[3], 2, 2));
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     () -> mh_updateArray.invoke(md, new byte[1], -1, 1));
        assertThrows(ArrayIndexOutOfBoundsException.class,
                     () -> mh_updateArray.invoke(md, new byte[0x30], 0xFFFFFFF0, 0x20));

        // Evil byte buffers
        assertThrows(Exception.class,
                     () -> mh_updateByteBuf.invoke(md, evilByteBuffer(new byte[1], 2, 1)));
        assertThrows(Exception.class,
                     () -> mh_updateByteBuf.invoke(md, evilByteBuffer(new byte[3], 2, 2)));
        assertThrows(Exception.class,
                     () -> mh_updateByteBuf.invoke(md, evilByteBuffer(new byte[1], -1, 1)));
        assertThrows(Exception.class,
                     () -> mh_updateByteBuf.invoke(md, evilByteBuffer(new byte[0x30], 0xFFFFFFF0, 0x20)));

        int digestLength = md.getDigestLength();
        assertThrows(IllegalArgumentException.class,
                     () -> mh_engineDigest.invoke(md, new byte[digestLength], 1, digestLength));
        assertThrows(IllegalArgumentException.class,
                     () -> mh_engineDigest.invoke(md, new byte[digestLength], -1, digestLength));
        assertThrows(IllegalArgumentException.class,
                     () -> mh_engineDigest.invoke(md, new byte[digestLength], 0, digestLength - 1));
        assertThrows(IllegalArgumentException.class,
                     () -> mh_engineDigest.invoke(md, new byte[digestLength], 0xFFFFFFFF, digestLength + 0x10));
    }

    private ByteBuffer evilByteBuffer(byte[] bytes, int offset, int len) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        Field f_offset = ByteBuffer.class.getDeclaredField("offset");
        Field f_limit = Buffer.class.getDeclaredField("limit");
        f_offset.setAccessible(true);
        f_limit.setAccessible(true);

        f_offset.set(buf, offset);
        f_limit.set(buf, len);

        return buf;
    }
}

