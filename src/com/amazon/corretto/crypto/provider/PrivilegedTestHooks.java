// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

@SuppressWarnings("unused") // invoked reflectively
class PrivilegedTestHooks {
    // When built with RNG test hooks enabled, the pattern specifies a bitmask of which RDRAND/RDSEED calls are allowed
    // to succeed. Each call will rotate right once, and use the bit rotated around to determine if the call should
    // fail.
    private static native boolean set_rng_success_pattern(long pattern);

    // Breaks rdseed entirely. Call set_rng_success_pattern to reset.
    // Requires RNG test hooks.
    private static native boolean break_rdseed();
}
