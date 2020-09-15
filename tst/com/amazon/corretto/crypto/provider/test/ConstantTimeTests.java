// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;


// Note: We don't actually test that these methods are constant time, just that they give the correct answers.
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
public class ConstantTimeTests {
    // A few common values which when combined can trigger edge cases
    private static final int[] TEST_VALUES = {Integer.MIN_VALUE, Integer.MIN_VALUE + 1, -2, -1, 0, 1, 2, Integer.MAX_VALUE - 1, Integer.MAX_VALUE};
    private static final Class<?> CONSTANT_TIME_CLASS;
    static {
        try {
            CONSTANT_TIME_CLASS = Class.forName("com.amazon.corretto.crypto.provider.ConstantTime");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }


    public static List<Arguments> testPairs() {
        final List<Arguments> result = new ArrayList<>();
        for (int a : TEST_VALUES) {
            for (int b : TEST_VALUES) {
                result.add(arguments(a, b));
            }
        }
        return result;
    }

    public static int[] testSingles() {
        return TEST_VALUES;
    }

    @ParameterizedTest
    @MethodSource("testSingles")
    public void testIsNonZero(int val) {
        final int expected = val != 0 ? 1 : 0;
        assertEquals(expected, sneaky("isNonZero", val));
    }

    @ParameterizedTest
    @MethodSource("testSingles")
    public void testIsZero(int val) {
        final int expected = val == 0 ? 1 : 0;
        assertEquals(expected, sneaky("isZero", val));
    }

    @ParameterizedTest
    @MethodSource("testSingles")
    public void testIsNegative(int val) {
        final int expected = val < 0 ? 1 : 0;
        assertEquals(expected, sneaky("isNegative", val));
    }

    @ParameterizedTest
    @MethodSource("testPairs")
    public void testEqual(int x, int y) {
        final int expected = x == y ? 1 : 0;
        assertEquals(expected, sneaky("equal", x, y));
    }

    @ParameterizedTest
    @MethodSource("testPairs")
    public void testGt(int x, int y) {
        final int expected = x > y ? 1 : 0;
        assertEquals(expected, sneaky("gt", x, y));
    }

    @ParameterizedTest
    @MethodSource("testSingles")
    public void testSelect(int selector) {
        final int a = 10;
        final int b = 11;
        final int expected = selector != 0 ? a : b;
        assertEquals(expected, sneaky("select", selector, a, b));
    }

    private static int sneaky(String name, int a) {
        try {
            return TestUtil.sneakyInvoke_int(CONSTANT_TIME_CLASS, name, a);
        } catch (final Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static int sneaky(String name, int a, int b) {
        try {
            return TestUtil.sneakyInvoke_int(CONSTANT_TIME_CLASS, name, a, b);
        } catch (final Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static int sneaky(String name, int a, int b, int c) {
        try {
            return TestUtil.sneakyInvoke_int(CONSTANT_TIME_CLASS, name, a, b, c);
        } catch (final Throwable t) {
            throw new AssertionError(t);
        }
    }
}
