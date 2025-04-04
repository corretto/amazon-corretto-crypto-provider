// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

/** Contains several constant time utilities */
final class ConstantTime {
  private static int LONG_UNSIGNED_SHIFT = Long.SIZE - 1;

  private ConstantTime() {
    // Prevent instantiation
  }

  /** Equivalent to {@code val != 0 ? 1 : 0} */
  static int isNonZero(int val) {
    return ((val | -val) >>> 31) & 0x01; // Unsigned bitshift
  }

  /** Equivalent to {@code val == 0 ? 1 : 0} */
  static int isZero(int val) {
    return 1 - isNonZero(val);
  }

  /** Equivalent to {@code val < 0 ? 1 : 0} */
  static int isNegative(int val) {
    return (val >>> 31) & 0x01;
  }

  /** Equivalent to {@code x == y ? 1 : 0} */
  static int equal(int x, int y) {
    final int difference = x - y;
    // Difference is 0 iff x == y
    return isZero(difference);
  }

  /** Equivalent to {@code x > y ? 1 : 0} */
  static int gt(int x, int y) {
    // Convert to long to avoid underflow
    final long xl = x;
    final long yl = y;
    final long difference = yl - xl;
    // If xl > yl, then difference is negative.
    // Thus, we can just return the sign-bit
    return (int) (difference >>> LONG_UNSIGNED_SHIFT); // Unsigned bitshift
  }

  /** Equivalent to {@code selector != 0 ? a : b} */
  static int select(int selector, int a, int b) {
    final int mask = isZero(selector) - 1;
    // Mask == -1 (all bits 1) iff selector != 0
    // Mask ==  0 (all bits 0) iff selector == 0

    final int combined = a ^ b;

    return b ^ (combined & mask);
  }

  /**
   * @return true iff all the bytes in the specified ranges are equal
   */
  static boolean equals(
      final byte[] a,
      final int aStart,
      final int aLen,
      final byte[] b,
      final int bStart,
      final int bLen) {

    Utils.checkArrayLimits(a, aStart, aLen);
    Utils.checkArrayLimits(b, bStart, bLen);

    if (aLen != bLen) {
      return false;
    }

    int result = 0;

    for (int i = 0; i < aLen; i++) {
      result |= a[aStart + i] ^ b[bStart + i];
    }

    return result == 0;
  }

  static boolean equals(final byte[] a, final int aStart, final int aLen, final byte[] b) {
    return equals(a, aStart, aLen, b, 0, b.length);
  }

  static boolean equals(final byte[] a, final byte[] b) {
    if (a == b) {
      return true;
    }
    if (a == null || b == null) {
      return false;
    }
    return equals(a, 0, a.length, b);
  }
}
