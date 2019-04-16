// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

// Note: Please consult the "How to Read JML" readme to understand the JML annotations
// in this file (contained in //@ or /*@ @*/ comments).

// The JML annotations in this file do not presently verify due to low-level issues
// in OpenJML, but these specifications are needed (and assumed) by InputBuffer.
// Specifications about the contents of the internal buffer have been commented out for now, 
// since InputBuffer does not reason about the buffer contents

//@ non_null_by_default
// @NotThreadSafe // Restore once replacement for JSR-305 available
class AccessibleByteArrayOutputStream extends OutputStream implements Cloneable {
    //@ spec_public
    private final int limit;
    //@ spec_public
    private byte[] buf;
    //@ spec_public
    private int count;
    //@ public invariant 0 <= count && count <= buf.length && buf.length <= limit;

    //@ normal_behavior
    //@   ensures this.count == 0 && this.limit == Integer.MAX_VALUE;
    //@   ensures this.buf.length > 0;
    //@ also private normal_behavior
    //@   ensures this.buf.length == 32;
    //@ pure
    AccessibleByteArrayOutputStream() {
        this(32, Integer.MAX_VALUE);
    }

    //@ normal_behavior
    //@   requires 0 <= capacity && capacity <= limit;
    //@   ensures this.limit == limit && this.count == 0;
    //@   ensures this.buf.length == capacity;
    //@ also exceptional_behavior
    //@   requires capacity < 0 || limit < 0 || limit < capacity;
    //@   signals_only IllegalArgumentException;
    //@ pure
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

    // Left as a TODO because the specs for Array::clone() are broken
    //@ also
    //@ public normal_behavior
    //@   assignable \everything;
    //@   ensures true;
    //@// pure - should be pure
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
    
    //@ represents outputBytes = buf;

    //@ also
    //@ public normal_behavior
    //@   requires 0 <= off && 0 <= len && off <= b.length - len && count <= limit - len;
    //@   assignable count; //, buf, buf[count .. count+len-1]; // old value of count
    //@   ensures count == \old(count) + len;
    //@   // ensures java.util.Arrays.equalArrays(b, off, buf, \old(count), len);
    //@   // TODO - rest of array, which might be copied, is unchanged
    //@ also
    //@ public exceptional_behavior
    //@   requires 0 > off || 0 > len || off > b.length - len || count > limit - len;
    //@   assignable \nothing;
    //@   {|
    //@     requires count > limit - len;
    //@     signals_only IllegalArgumentException;
    //@     also
    //@     requires count <= limit - len && (len < 0 || off < 0 || off > b.length - len);
    //@     signals_only IndexOutOfBoundsException;
    //@   |}
    //@ spec_bigint_math code_safe_math
    @Override
    public void write(final byte[] b, final int off, final int len) {
        //@ show count, len, off, b.length, limit, Integer.MAX_VALUE;
        growCapacity(count + len);
        System.arraycopy(b, off, buf, count, len);
        count += len;
    }

    //@ also
    //@ public normal_behavior
    //@   requires count < limit && count < Integer.MAX_VALUE;
    //@   assignable count; //, buf, buf[count];
    //@   // ensures buf[\old(count)] == b;
    //@   ensures count == \old(count) + 1;
    //@   // TODO - rest of array, which might be copied, is unchanged
    //@ also
    //@ public exceptional_behavior
    //@   requires count < Integer.MAX_VALUE && count == limit;
    //@   assignable \nothing;
    //@   signals_only IllegalArgumentException;
    //@   // overflow would result in OutOfMemoryError
    //@ code_java_math  // Ignore cast range overflow
    @Override
    public void write(final int b) {
        growCapacity(count + 1);
        buf[count++] = (byte) b;
    }

    //@ normal_behavior
    //@   ensures \result == count;
    //@ spec_public pure
    int size() {
        return count;
    }

    //@ normal_behavior
    //@   ensures \result == buf;
    //@ pure
    byte[] getDataBuffer() {
        return buf;
    }

    //@ // Does not overwrite all of the buffer, just what is expected to have been written. However,
    //@ // we can prove that the rest is still zero using an invariant that all beyond what has been written
    //@ // is zero (assuming JML correctly zero-initializes arrays)
    //@ normal_behavior
    //@   assignable count; //, buf[*];
    //@   ensures count == 0;
    //@   // ensures (\forall int i; 0 <= i && i < \old(count); buf[i] == 0);
    void reset() {
        Arrays.fill(buf, 0, count, (byte) 0);
        count = 0;
    }

    //@ normal_behavior
    //@   old int length = bbuff.remaining();
    //@   requires count + bbuff.remaining() <= limit;
    //@   assignable count, bbuff.position; //, buf, buf[*]; // old value of count
    //@   ensures count == \old(count) + length;
    //@   ensures bbuff.position == bbuff.limit;
    //@   // ensures java.util.Arrays.equalArrays(bbuff.hb, \old(bbuff.position), buf, \old(count), length);
    //@   ensures (* rest of array, which might be copied, is unchanged *);
    void write(final ByteBuffer bbuff) {
        final int length = bbuff.remaining();
        growCapacity(count + length);
        bbuff.get(buf, count, length);
        count += length;
    }
    
    //@ public normal_behavior
    //@   requires 0 <= x && x <= Integer.MAX_VALUE/2;
    //@   ensures x << 1 == x * 2;
    //@ pure
    //@ model public void lemma_can_be_doubled(int x) {}

    //@ private normal_behavior
    //@   requires newCapacity >= 0 && newCapacity <= limit;
    //@   {|
    //@     requires newCapacity <= buf.length;
    //@     assignable \nothing;
    //@   also
    //@     requires newCapacity > buf.length;
    //@     assignable buf; //, buf[*];
    //@     ensures \fresh(buf);
    //@     ensures buf.length >= newCapacity;
    //@     ensures (* new array has data from old array before zeroing *);
    //@     ensures (* rest of new array is 0 *);
    //@     ensures (* old buffer is zeroed *);
    //@   |}
    //@   ensures newCapacity <= buf.length;
    //@ also private exceptional_behavior
    //@   requires newCapacity >= 0 && newCapacity > limit;
    //@   assignable \nothing;
    //@   // OutOfMemoryError cannot be specified by JML even though it is thrown
    //@   signals_only IllegalArgumentException;
    //@ code_java_math  // allow overflow in code
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
        
        //@ use lemma_can_be_doubled(buf.length);
        final int predictedSize = Math.min(limit, buf.length << 1);
        final byte[] tmp = new byte[Math.max(predictedSize, newCapacity)];
        System.arraycopy(buf, 0, tmp, 0, buf.length);
        final byte[] toZeroize = buf;
        buf = tmp;
        Arrays.fill(toZeroize, (byte) 0);
    }
}
