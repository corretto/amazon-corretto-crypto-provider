// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;

// TODO: merge this class and AesGcmSpi.ShimArray
class ShimByteBuffer {
  public final ByteBuffer directByteBuffer;
  public final byte[] array;
  public final int offset;

  // backingByteBuffer is only used when the byteBuffer is not direct nor has a backing array.
  private final ByteBuffer backingByteBuffer;

  ShimByteBuffer(final ByteBuffer byteBuffer, final boolean isInput) {
    if (byteBuffer.hasArray()) {
      backingByteBuffer = null;

      directByteBuffer = null;
      array = byteBuffer.array();
      offset = byteBuffer.position();
      return;
    }

    if (byteBuffer.isDirect()) {
      backingByteBuffer = null;

      directByteBuffer = byteBuffer;
      array = null;
      offset = byteBuffer.position();
      return;
    }
    // The original ByteBuffer is not direct and its backing array is not accessible. An example is
    // a read-only ByteBuffer wrapping a byte[].
    backingByteBuffer = byteBuffer.duplicate();

    directByteBuffer = null;
    array = new byte[byteBuffer.remaining()];
    if (isInput) {
      backingByteBuffer.duplicate().get(array);
    }
    offset = 0;
  }

  void writeBack(final int len) {
    if (backingByteBuffer != null) {
      backingByteBuffer.put(array, 0, len);
    }
  }
}
