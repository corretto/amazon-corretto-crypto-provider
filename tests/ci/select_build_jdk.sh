#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# select_kem_capable_java_home: ensure JAVA_HOME points to a JDK that exposes the
# javax.crypto.KEM API. ACCP now requires such a JDK at build time to compile the
# ML-KEM Multi-Release overlay. The KEM API is GA in JDK 21+ and backported into
# some JDK 17 builds (e.g. Corretto 17), but is absent from a stock JDK 17 and
# from JDK 8/11.
#
# Selection order (first that can compile "import javax.crypto.KEM" wins):
#   1. the current JAVA_HOME (left unchanged when already capable),
#   2. TEST_JAVA_HOME, if set (the CI's target runtime -- often 17+),
#   3. the newest JDK installed under /usr/lib/jvm.
# On success JAVA_HOME/PATH point to a capable JDK; on failure returns non-zero.
# This only chooses the *build* JDK -- tests still run on TEST_JAVA_HOME, which
# the callers pass to gradle via -DTEST_JAVA_HOME.
select_kem_capable_java_home() {
    local probe_dir candidate
    probe_dir="$(mktemp -d)"
    printf 'import javax.crypto.KEM; public final class KemProbe {}\n' > "${probe_dir}/KemProbe.java"

    _accp_javac_has_kem() {
        [ -n "${1:-}" ] && [ -x "${1}/bin/javac" ] \
            && "${1}/bin/javac" -d "${probe_dir}" "${probe_dir}/KemProbe.java" >/dev/null 2>&1
    }

    if _accp_javac_has_kem "${JAVA_HOME:-}"; then
        rm -rf "${probe_dir}"; unset -f _accp_javac_has_kem; return 0
    fi

    for candidate in "${TEST_JAVA_HOME:-}" $(ls -d /usr/lib/jvm/java-* 2>/dev/null | sort -rV || true); do
        if _accp_javac_has_kem "${candidate}"; then
            echo "select_build_jdk: JAVA_HOME (${JAVA_HOME:-unset}) lacks javax.crypto.KEM; building with ${candidate}"
            export JAVA_HOME="${candidate}"
            export PATH="${JAVA_HOME}/bin:${PATH}"
            rm -rf "${probe_dir}"; unset -f _accp_javac_has_kem; return 0
        fi
    done

    rm -rf "${probe_dir}"; unset -f _accp_javac_has_kem
    echo "select_build_jdk: ERROR - no JDK exposing javax.crypto.KEM found; ACCP needs JDK 21+ or a KEM-backported JDK 17 (e.g. Corretto 17) to build." >&2
    return 1
}
