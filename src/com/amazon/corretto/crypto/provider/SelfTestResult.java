// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.util.Objects;

public class SelfTestResult {
    private final SelfTestStatus status;
    private final Throwable throwable;

    public SelfTestStatus getStatus() {
        return status;
    }

    public Throwable getThrowable() {
        return throwable;
    }

    public SelfTestResult(SelfTestStatus status) {
        if (status == SelfTestStatus.FAILED) {
            throw new IllegalArgumentException("Must provide exception for failed result");
        }

        this.status = status;
        this.throwable = null;
    }

    public SelfTestResult(Throwable throwable) {
        this.status = SelfTestStatus.FAILED;
        this.throwable = throwable;
    }

    public SelfTestResult combine(SelfTestResult other) {
        if (status.combine(other.getStatus()) == status) {
            return this;
        } else {
            return other;
        }
    }

    @Override public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final SelfTestResult that = (SelfTestResult) o;
        return status == that.status;
    }

    @Override public int hashCode() {
        return Objects.hash(status);
    }

    @Override public String toString() {
        return "SelfTestResult{" +
                "status=" + status +
                ", throwable=" + throwable +
                '}';
    }
}
