// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;

// TODO: merge this class and AesGcmSpi.ShimArray

/**
 * This class simplifies working with a ByteBuffer when passed to native methods. The class provides
 * three public fields that can be accessed after instantiation.
 *
 * <p>The memory represented by a ByteBuffer falls into one of the following three categories:
 *
 * <ol>
 *   <li>Accessible array ({@code assert(ByteBuffer::hasArray())})
 *   <li>Direct memory ({@code assert(ByteBuffer::isDirect())})
 *   <li>Neither has accessible array, nor is direct.
 * </ol>
 *
 * <p>After creating an instance of this class, the following assertions will hold:
 *
 * <pre>{@code
 * ShimByteBuffer shbb = new ShimByteBuffer(byteBuffer, true/false);
 * assert((shbb.directByteBuffer == null) || (shbb.array == null));
 * assert((shbb.directByteBuffer != null) || (shbb.array != null));
 * }</pre>
 *
 * <p>If a ByteBuffer is direct then {@code directByteBuffer} will not be null, otherwise, {@code
 * array} will not be null.
 *
 * <p>In case the ByteBuffer neither has accessible array, nor is direct, then this class allocates
 * a temporary byte array. If the original ByteBuffer is an input buffer, then the content is copied
 * into the temporary byte array.
 *
 * <p>When a ByteBuffer needs to be processed in the native code, we recommend creating an instance
 * of {@code ShimByteBuffer} and pass the public members to the native code. The C++ class {@code
 * JBinaryBlob} can be used to turn a pair of {@code directByteBuffer} and {@code array} into {@code
 * uint8_t*}.
 *
 * <p>Please have a look at {@code AesCbcSpi::engineDoFinal(ByteBuffer input, ByteBuffer output)}
 * for an example of how this class is used.
 */
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
      offset = byteBuffer.arrayOffset() + byteBuffer.position();
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
