// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

public enum SelfTestStatus {
    /* The order of the following status enums determines which one "wins" when two results are combined. Later results
     * win over earlier ones.
     */

    NOT_RUN, RECURSIVELY_INVOKED, PASSED, FAILED;

    /**
     * Merges multiple results for a single test to determine the overall result for this test.
     * @param other
     * @return
     */
    SelfTestStatus combine(SelfTestStatus other) {
        if (other.ordinal() > ordinal()) {
            return other;
        } else {
            return this;
        }
    }

    /**
     * Merges multiple results for different tests to determine the overall result for the suite.
     * @param other
     * @return
     */
    public SelfTestStatus combineMultipleTests(final SelfTestStatus other) {
        if (this == FAILED || other == FAILED) return FAILED;
        if (this == NOT_RUN || other == NOT_RUN) return NOT_RUN;
        if (this == RECURSIVELY_INVOKED || other == RECURSIVELY_INVOKED) return RECURSIVELY_INVOKED;

        if (this == PASSED && other == PASSED) return PASSED;

        // should be unreachable
        throw new AssertionError("Non-exhaustive cases in combineMultipleTests");
    }
}
