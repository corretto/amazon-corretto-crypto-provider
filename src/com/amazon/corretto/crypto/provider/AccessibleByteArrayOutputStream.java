// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

class AccessibleByteArrayOutputStream extends OutputStream implements Cloneable {
    private final int limit;
    private byte[] buf;
    private int count;

    AccessibleByteArrayOutputStream() {
        this(32, Integer.MAX_VALUE);
    }

    AccessibleByteArrayOutputStream(final int capacity, final int limit) {
        if (limit < 0) {
            throw new IllegalArgumentException("Limit must be non-negative");
        }
        if (capacity < 0 || capacity > limit) {
            throw new IllegalArgumentException("Capacity must be non-negative and less than limit");
        }
        buf = capacity == 0 ? Utils.EMPTY_ARRAY : new byte[capacity];
        this.limit = limit;
        count = 0;
    }

    @Override
    public AccessibleByteArrayOutputStream clone() {
        try {
            final AccessibleByteArrayOutputStream cloned = (AccessibleByteArrayOutputStream) super.clone();
            cloned.buf = buf.clone();
            return cloned;
        } catch (final CloneNotSupportedException ex) {
            throw new RuntimeCryptoException("Unexpected exception", ex);
        }
    }

    @Override
    public void write(final byte[] b, final int off, final int len) {
        growCapacity(count + len);
        System.arraycopy(b, off, buf, count, len);
        count += len;
    }

    @Override
    public void write(final int b) {
        growCapacity(count + 1);
        buf[count++] = (byte) b;
    }

    int size() {
        return count;
    }

    /** Returns the actual internal field containing the data.
     * Callers <em>MUST NOT</em> leak this value outside of ACCP without careful analysis
     * as any further use of this object may cause the contents of the returned array to change.
     */
    byte[] getDataBuffer() {
        return buf;
    }

    void reset() {
        Arrays.fill(buf, 0, count, (byte) 0);
        count = 0;
        // TODO: Consider keeping track of length at reset.
        // If it is consistently below the maximum value we may want to trim
        // down to save on memory.
    }

    void write(final ByteBuffer bbuff) {
        final int length = bbuff.remaining();
        growCapacity(count + length);
        bbuff.get(buf, count, length);
        count += length;
    }

    private void growCapacity(final int newCapacity) {
        if (newCapacity < 0) {
            throw new OutOfMemoryError();
        }
        if (newCapacity > limit) {
            throw new IllegalArgumentException(String.format("Exceeded capacity limit %d. Requested %d", limit,
                    newCapacity));
        }
        if (newCapacity <= buf.length) {
            return;
        }
        final int predictedSize = Math.min(limit, buf.length << 1);

        final byte[] tmp = Arrays.copyOf(buf, Math.max(predictedSize, newCapacity));
        final byte[] toZeroize = buf;
        buf = tmp;
        Arrays.fill(toZeroize, 0, count, (byte) 0);
    }
}
