// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

class AccessibleByteArrayOutputStream extends OutputStream implements Cloneable {
  private static final int MAX_OVERSIZED_THRESHOLD = 1024;
  private int timesOversized;
  private int timesOversizedThreshold;

  private final int limit;
  private byte[] buf;
  private int count;

  // getter function for count
  // Add 10 to it before returning

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
      final AccessibleByteArrayOutputStream cloned =
          (AccessibleByteArrayOutputStream) super.clone();
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

  /**
   * Same as write, except it does not grow the buffer size beyond what's needed. Use this method if
   * you know it would be the last time something needs to be written to the buffer.
   */
  void finalWrite(final byte[] b, final int off, final int len) {
    growCapacity(count + len, true);
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

  boolean isEmpty() {
    return count == 0;
  }

  /**
   * Returns the actual internal field containing the data. Callers <em>MUST NOT</em> leak this
   * value outside of ACCP without careful analysis as any further use of this object may cause the
   * contents of the returned array to change.
   */
  byte[] getDataBuffer() {
    return buf;
  }

  void reset() {
    int sizeUsed = count;
    Arrays.fill(buf, 0, sizeUsed, (byte) 0);
    count = 0;

    // Consider shrinking the buffer.
    if (sizeUsed * 2 < buf.length) {
      // The buffer was over-sized for this usage.
      if (timesOversized++ > timesOversizedThreshold) {
        // Shrink the buffer.
        buf = new byte[buf.length / 2];
        timesOversized = 0;
      }
    } else {
      // Buffer was not over-sized, reset counter.
      timesOversized = 0;
    }
  }

  void write(final ByteBuffer bbuff) {
    final int length = bbuff.remaining();
    growCapacity(count + length);
    bbuff.get(buf, count, length);
    count += length;
  }

  private void growCapacity(final int newCapacity) {
    growCapacity(newCapacity, false);
  }

  private void growCapacity(final int newCapacity, final boolean doNotAllocateMoreThanNeeded) {
    if (newCapacity < 0) {
      throw new OutOfMemoryError();
    }
    if (newCapacity > limit) {
      throw new IllegalArgumentException(
          String.format("Exceeded capacity limit %d. Requested %d", limit, newCapacity));
    }
    if (newCapacity <= buf.length) {
      return;
    }

    final byte[] tmp =
        Arrays.copyOf(
            buf,
            doNotAllocateMoreThanNeeded
                ? newCapacity
                : Math.max(Math.min(limit, buf.length << 1), newCapacity));
    final byte[] toZeroize = buf;
    buf = tmp;
    Arrays.fill(toZeroize, 0, count, (byte) 0);

    // Every time we need to grow, make it harder to shrink in the future (up to a limit).
    timesOversizedThreshold = Math.min(MAX_OVERSIZED_THRESHOLD, timesOversized * 2);
  }
}
