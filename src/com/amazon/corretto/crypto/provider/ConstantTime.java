// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

/**
 * Contains several constant time utilities
 */
final class ConstantTime {
    private ConstantTime() {
        // Prevent instantiation
    }

    /**
     * Equivalent to {@code val != 0 ? 1 : 0}
     */
    static final int isNonZero(int val) {
        return ((val | -val) >>> 31) & 0x01; // Unsigned bitshift
    }

    /**
     * Equivalent to {@code val == 0 ? 1 : 0}
     */
    static final int isZero(int val) {
         return 1 - isNonZero(val);
    }

    /**
     * Equivalent to {@code val < 0 ? 1 : 0}
     */
    static final int isNegative(int val) {
        return (val >>> 31) & 0x01;
    }

    /**
     * Equivalent to {@code x == y ? 1 : 0}
     */
    static final int equal(int x, int y) {
        final int difference = x - y;
        // Difference is 0 iff x == y
        return isZero(difference);
    }

    /**
     * Equivalent to {@code x > y ? 1 : 0}
     */
    static final int gt(int x, int y) {
        // Convert to long to avoid underflow
        final long xl = x;
        final long yl = y;
        final long difference = yl - xl;
        // If xl > yl, then difference is negative.
        // Thus, we can just return the sign-bit
        return (int) ((difference >>> 63) & 0x01); // Unsigned bitshift
    }

    /**
     * Equivalent to {@code selector != 0 ? a : b}
     */
    static final int select(int selector, int a, int b) {
        final int mask = isZero(selector) - 1;
        // Mask == -1 (all bits 1) iff selector != 0
        // Mask ==  0 (all bits 0) iff selector == 0

        final int combined = a ^ b;

        return b ^ (combined & mask);
    }
}
