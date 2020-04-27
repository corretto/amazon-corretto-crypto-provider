// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

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
            // Force loading library
            if (AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError() != null) {
                return false;
            }
            NativeTestHooks.hasRdseed();
            return true;
        } catch (final Throwable t) {
            return false;
        }
    }

    public static class RequireHooks implements ExecutionCondition {
        private static final ConditionEvaluationResult ENABLED = ConditionEvaluationResult.enabled("Hooks present");
        private static final ConditionEvaluationResult DISABLED = ConditionEvaluationResult.disabled("Hooks missing");

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            return hasNativeHooks() ? ENABLED : DISABLED;
        }
    }
}

