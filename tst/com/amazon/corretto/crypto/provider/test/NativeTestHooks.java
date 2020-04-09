// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import org.junit.Assume;

/**
 * Hooks for {@link NativeTest}
 */
public class NativeTestHooks {
    // Note: Since we're not sealing this package by including it in the JAR, any native functions in here need to be
    // generally safe to call. Unsafe functions should go in PrivilegedTestHooks instead.

    public static native void throwException();
    public static native void getBytes(byte[] array, int offset, int length, int off2, int len2);
    public static native void putBytes(byte[] array, int offset, int length, int off2, int len2);
    public static native void getBytesLocked(byte[] array, int offset, int length, int off2, int len2);
    public static native void putBytesLocked(byte[] array, int offset, int length, int off2, int len2);
    public static native void borrowCheckRange(byte[] array, int offset, int length, int off2, int len2);

    public static native boolean rdrand(byte[] array);
    public static native boolean rdseed(byte[] array);

    public static native boolean hasRdseed();

    public static boolean hasNativeHooks() {
        try {
            NativeTestHooks.hasRdseed();
            return true;
        } catch (final Throwable t) {
            return false;
        }
    }
}

