// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.NativeTestHooks.throwException;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith({TestResultLogger.class, NativeTestHooks.RequireHooks.class})
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class NativeTest {

    @Test
    public void testBasicExceptions() throws Exception {
        try {
            throwException();
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("Test exception message"));
        }
    }

    @Test
    public void testOutOfBoundsAccess() throws Exception {
        testAccess(NativeTestHooks::getBytes);
        testAccess(NativeTestHooks::getBytesLocked);
        testAccess(checkPutResult(NativeTestHooks::putBytes));
        testAccess(checkPutResult(NativeTestHooks::putBytesLocked));
        testAccess(NativeTestHooks::borrowCheckRange);
    }

    private ArrayAccess checkPutResult(final ArrayAccess putter) {
        return (array, off1, len1, off2, len2) -> {
            putter.access(array, off1, len1, off2, len2);

            for (int i = 0; i < len2; i++) {
                int index = off1 + off2 + i;
                if (array[index] != 100+i) {
                    assertEquals(array[index], 100+i);
                }
            }
        };
    }

    private void testAccess(ArrayAccess op) {
        byte[] array = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        op.access(array, 0, 10, 0, 10);
        op.access(array, 0, 10, 0, 5);
        op.access(array, 0, 10, 5, 5);
        op.access(array, 5, 5, 0, 5);
        op.access(array, 0, 5, 0, 5);

        assertOOB(() -> op.access(array, 1, 10, 0, 0));
        assertOOB(() -> op.access(array, -1, 10, 0, 0));
        assertOOB(() -> op.access(array, 0, -10, 0, 0));
        assertOOB(() -> op.access(array, 0, 11, 0, 0));
        assertOOB(() -> op.access(array, 0, 10, 0, 11));
        assertOOB(() -> op.access(array, 0, 10, 1, 10));
        assertOOB(() -> op.access(array, 0, 10, -1, 10));
        assertOOB(() -> op.access(array, 0, 10, 0, -10));
    }

    private void assertOOB(ThrowingRunnable r) {
        assertThrows(ArrayIndexOutOfBoundsException.class, r);
    }
    
    private interface ArrayAccess {
        void access(byte[] array, int off1, int len1, int off2, int len2);
    }
}

