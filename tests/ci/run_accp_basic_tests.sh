#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Testing non-FIPS is the default.
testing_fips=false
testing_experimental_fips=false
testing_fips_self_test_skip_abort=false
testing_fips_test_break=false
testing_latest_awslc=false
target_jdk_version=""

# Depending on lcov version, either inconsistent or source needs to be passed
lcov_ignore=source
while [[ $# -gt 0 ]]; do
    echo "processing $1"
    case $1 in
    --fips)
        testing_fips=true
        shift
        ;;
    --lcov-ignore)
        lcov_ignore="$2"
        shift 2
        ;;
    --experimental-fips)
        testing_experimental_fips=true
        shift
        ;;
    --fips-self-test-failure-no-abort)
        testing_fips=true
        testing_experimental_fips=true # TODO: can be deleted when AWS-LC-FIPS supports callback
        testing_fips_self_test_skip_abort=true
        testing_fips_test_break=true
        shift
        ;;
    --target-jdk-version)
        target_jdk_version="$2"
        shift 2
        ;;
    --latest-awslc)
        # Use the latest (main branch) AWS-LC commit instead of the currently checked in submodule.
        testing_latest_awslc=true
        shift
        ;;
    *)
        echo "$1 is not supported."
        exit 1
        ;;
    esac
done

# Parse and check which JDK version we're testing upon.
version=$($TEST_JAVA_HOME/bin/java -version 2>&1 | head -1 | cut -d'"' -f2 | sed '/^1\./s///' | cut -d'.' -f1)

awslc_src_override=""
if [[ "${testing_latest_awslc}" == "true" ]]; then
    echo "Testing against AWS-LC main branch tip"
    awslc_src="${PWD}/build/awslc-src"
    rm -rf "${awslc_src}"
    mkdir -p "${awslc_src}"
    git clone https://github.com/aws/aws-lc.git "${awslc_src}"
    awslc_src_override="-DAWSLC_SRC_DIR=${awslc_src} -DAWSLC_GITVERSION=main"
fi

# The build JDK (JAVA_HOME) must be JDK 17+ and expose the javax.crypto.KEM API
# (JDK 21+ or a KEM-backported JDK 17 such as Corretto 17) so the ML-KEM
# Multi-Release overlay can be compiled. We can still test on older runtimes
# (JDK 8/11) via the TEST_JAVA_HOME property.
if (( "$version" <= "10" )); then
    ./gradlew \
        -DTEST_JAVA_HOME=$TEST_JAVA_HOME \
        -DTEST_JAVA_MAJOR_VERSION=$version \
        -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
        -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
        -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
        -DFIPS=$testing_fips \
        -DLCOV_IGNORE=$lcov_ignore \
        -DTARGET_JDK_VERSION=$target_jdk_version \
        $awslc_src_override \
        coverage test
    exit $?
fi

# Build with JAVA_HOME (assumed JDK 17+) and run the tests on TEST_JAVA_HOME,
# which may be a newer runtime equal to the build JDK or an older one (JDK 11)
# that ACCP still supports. Do not overwrite JAVA_HOME with the test JDK: the
# build JDK must stay KEM-capable to compile the ML-KEM overlay.
./gradlew \
    -DTEST_JAVA_HOME=$TEST_JAVA_HOME \
    -DTEST_JAVA_MAJOR_VERSION=$version \
    -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
    -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
    -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
    -DFIPS=$testing_fips \
    -DLCOV_IGNORE=$lcov_ignore \
    -DTARGET_JDK_VERSION=$target_jdk_version \
    $awslc_src_override \
    release
