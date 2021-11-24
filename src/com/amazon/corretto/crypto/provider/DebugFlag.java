// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.util.EnumSet;

/**
 * Indicates whether a given debug mode is enabled for ACCP. None of these modes
 * may compromise the security of ACCP but they are permitted to have
 * significant performance costs.
 *
 * These are used by passing them by name (case-insensitive) to the
 * {@code com.amazon.corretto.crypto.provider.debug} system property. Example:
 * {@code -Dcom.amazon.corretto.crypto.provider.debug=FreeTrace}.
 *
 * Alternatively you can enable all debug flags with the magic value of "ALL".
 */
enum DebugFlag {
    /** Trace when native values are created and freed. */
    FREETRACE,
    /**
     * Increases the verbosity of logs.
     * May still need to be combined with increasing the log level of your configured logger.
     */
    VERBOSELOGS;

    private static final EnumSet<DebugFlag> ENABLED_FLAGS = EnumSet.noneOf(DebugFlag.class);

    static {
        Utils.optionsFromProperty(DebugFlag.class, ENABLED_FLAGS, "debug");
    }

    static boolean isEnabled(final DebugFlag flag) {
        return ENABLED_FLAGS.contains(flag);
    }

    boolean isEnabled() {
        return isEnabled(this);
    }
}
