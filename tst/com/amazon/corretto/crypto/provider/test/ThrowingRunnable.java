// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

@FunctionalInterface
interface ThrowingRunnable {
    void run() throws Throwable;
}
