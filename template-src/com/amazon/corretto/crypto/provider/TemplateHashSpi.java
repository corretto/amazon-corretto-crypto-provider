// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.util.Arrays;


/**
 * Template for hash function bindings. Unfortunately using openssl's common EVP interface for hash functions introduces
 * significant performance overhead (to the point that the default JCE provider is faster for &lt;= 32 byte hashes).
 * As such we build direct bindings to the older interfaces for each of our supported hash functions - since these
 * are nearly identical, though, we use templates on both the Java and C++ sides to accomplish this.
 *
 * To further improve performance, we avoid using the C++ heap to allocate the state datastructure for our hash function
 * - instead, we allocate a java byte array and put the hash state in it directly. This is safe as long as 1) byte[]s
 * are aligned properly (seems to be the case due to Java object headers) and 2) no native-side pointers exist pointing
 * inside the hash function state structure. Since the latter is currently true and changing it would break the openssl
 * ABI we should be safe. By doing this hack, then, we avoid malloc/free overheads as well as Java finalizer overhead,
 * and can avoid a native call for initializing the hash function (by instead cloning a copy of the initial state of the
 * hash function).
 */
public final class TemplateHashSpi extends MessageDigestSpi implements Cloneable {
    private static final String HASH_NAME = "@@@HASH_NAME@@@";
    private static final int HASH_SIZE;
    private static final byte[] INITIAL_CONTEXT;

    private byte[] myContext;
    private InputBuffer<byte[], byte[]> buffer;

    static {
        Loader.checkNativeLibraryAvailability();

        INITIAL_CONTEXT = new byte[getContextSize()];

        initContext(INITIAL_CONTEXT);
        HASH_SIZE = getHashSize();
    }

    /**
     * Single-shot digest routine - digests the given byte array and immediately returns the result
     * @param digest Output buffer - must have at least getHashSize() bytes
     * @param buf Input buffer
     */
    // NOTE: This method trusts that all of the array lengths and bufLen are sane.
    static native void fastDigest(byte[] digest, byte[] buf, int bufLen);

    /**
     * @return The size of result hashes for this hash function
     */
    private static native int getHashSize();

    /**
     * The size of the native context datastructure
     */
    private static native int getContextSize();

    /**
     * Creates an initial native context datastructure and places it in the context byte array.
     *
     * Normally this is called once, during class static initialization, and we avoid subsequent native entries to this
     * routine by cloning the context we got during startup.
     */
    private static native void initContext(byte[] context);

    /**
     * Updates a native context array with some bytes from a byte array
     * @param context The native context array to update
     * @param buf Buffer to update from
     * @param offset Offset within buf
     * @param length Length within buf
     */
    private static native void updateContextByteArray(byte[] context, byte[] buf, int offset, int length);
    private static void synchronizedUpdateContextByteArray(byte[] context, byte[] buf, int offset, int length) {
        synchronized (context) {
            updateContextByteArray(context, buf, offset, length);
        }
    }

    /**
     * Updates a native context array with some bytes from a native byte buffer. Note that the native-side code does not
     * check offset and length; Java code must do this.
     *
     * @param context The native context array to update
     * @param buf Buffer to update from
     */
    private static native void updateNativeByteBuffer(byte[] context, ByteBuffer buf);
    private static void synchronizedUpdateNativeByteBuffer(byte[] context, ByteBuffer buf) {
        synchronized (context) {
            updateNativeByteBuffer(context, buf);
        }
    }

    /**
     * Finishes the digest operation. The native context is left in an undefined state.
     *
     * @param context Context buffer
     * @param digest Output buffer. Must be at least offset + getHashSize() bytes long
     * @param offset Offset within output buffer
     */
    private static native void finish(byte[] context, byte[] digest, int offset);
    private static void synchronizedFinish(byte[] context, byte[] digest, int offset) {
        synchronized (context) {
            finish(context, digest, offset);
        }
    }

    private byte[] resetContext() {
        System.arraycopy(INITIAL_CONTEXT, 0, myContext, 0, INITIAL_CONTEXT.length);
        return myContext;
    }

    public TemplateHashSpi() {
        Loader.checkNativeLibraryAvailability();
        myContext = INITIAL_CONTEXT.clone();

        this.buffer = new InputBuffer<byte[], byte[]>(1024)
            .withInitialStateSupplier(this::resetContext)
            .withUpdater(TemplateHashSpi::synchronizedUpdateContextByteArray)
            .withUpdater(TemplateHashSpi::synchronizedUpdateNativeByteBuffer)
            .withDoFinal((context) -> {
                final byte[] result = new byte[HASH_SIZE];
                synchronizedFinish(context, result, 0);
                return result;
            })
            .withSinglePass((src, offset, length) -> {
                if (offset != 0 || length != src.length) {
                    src = Arrays.copyOf(src, length);
                    offset = 0;
                }
                final byte[] result = new byte[HASH_SIZE];
                fastDigest(result, src, src.length);
                return result;
            })
            .withStateCloner((context) -> context.clone());
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        buffer.update(input, offset, length);
    }

    @Override
    protected void engineUpdate(ByteBuffer buf) {
        buffer.update(buf);
    }

    @Override
    protected int engineGetDigestLength() {
        return HASH_SIZE;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object clone() {
        try {
            TemplateHashSpi clonedObject = (TemplateHashSpi)super.clone();

            clonedObject.myContext = myContext.clone();
            clonedObject.buffer = (InputBuffer<byte[], byte[]>) buffer.clone();

            return clonedObject;
        } catch (CloneNotSupportedException e) {
            throw new Error("Unexpected CloneNotSupportedException", e);
        }
    }

    @Override
    protected byte[] engineDigest() {
        try {
            return buffer.doFinal();
        } finally {
            engineReset();
        }
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        if (len < HASH_SIZE) throw new IllegalArgumentException("Buffer length too small");
        final byte[] digest = engineDigest();
        try {
            System.arraycopy(digest, 0, buf, offset, HASH_SIZE);
        } catch (final ArrayIndexOutOfBoundsException ex) {
            throw new IllegalArgumentException(ex);
        }
        return HASH_SIZE;
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }
}
