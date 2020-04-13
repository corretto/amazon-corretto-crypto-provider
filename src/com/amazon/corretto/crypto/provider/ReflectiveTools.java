// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;

final class ReflectiveTools {
    private static MethodHandle mh_getArray;
    private static MethodHandle mh_arrayOffset;

    static {
        AccessController.doPrivileged((PrivilegedAction<Void>)ReflectiveTools::initReflection);
    }

    private static Void initReflection() {
        try {
            enableByteBufferReflection();
        } catch (Throwable t) {
            disableByteBufferReflection();
        }

        return null;
    }

    // Package-private visible helpers for use by test code
    static void enableByteBufferReflection() throws NoSuchFieldException, IllegalAccessException {
        // First get a Lookup instance that bypasses access checks
        Field IMPL_LOOKUP_FIELD = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
        IMPL_LOOKUP_FIELD.setAccessible(true);
        MethodHandles.Lookup LOOKUP = (MethodHandles.Lookup) IMPL_LOOKUP_FIELD.get(null);

        // Now dig into the guts of ByteBuffer
        mh_getArray = LOOKUP.findGetter(ByteBuffer.class, "hb", byte[].class)
                            .asType(MethodType.methodType(byte[].class, ByteBuffer.class));
        mh_arrayOffset = LOOKUP.findGetter(ByteBuffer.class, "offset", Integer.TYPE)
                               .asType(MethodType.methodType(Integer.class, ByteBuffer.class));
    }

    static void disableByteBufferReflection() {
        // If we failed to do our reflective hackery, just disable all this sneaky stuff by always returning null
        // from mh_getArray.
        mh_getArray =
            MethodHandles.dropArguments(
                MethodHandles.constant(byte[].class, null),
                0,
                ByteBuffer.class
            );
    }

    /**
     * Obtains an array from a ByteBuffer. This allows us to access the byte[] backing a read-only byte buffer, by
     * reflecting into the private array field.
     */
    static byte[] getArray(ByteBuffer buf) {
        try {
            return (byte[]) mh_getArray.invokeExact(buf);
        } catch (Throwable throwable) {
            throw new Error("unexpected error", throwable);
        }
    }

    /**
     * Obtains the array offset from a ByteBuffer.
     */
    static int getArrayOffset(ByteBuffer buf) {
        try {
            return (Integer) mh_arrayOffset.invokeExact(buf);
        } catch (Throwable throwable) {
            throw new Error("unexpected error", throwable);
        }
    }
}
