#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Testing non-FIPS is the default.
testing_fips=false
testing_experimental_fips=false
testing_fips_self_test_skip_abort=false
testing_fips_test_break=false

while [[ $# -gt 0 ]]; do
    case ${1} in
    --fips)
      testing_fips=true
      ;;
    --experimental-fips)
      testing_experimental_fips=true
      ;;
    --fips-self-test-failure-no-abort)
      testing_fips=true
      testing_experimental_fips=true # TODO: can be deleted when AWS-LC-FIPS supports callback
      testing_fips_self_test_skip_abort=true
      testing_fips_test_break=true
      ;;
    *)
      echo "${1} is not supported."
      exit 1
      ;;
    esac
    # Check next option -- key/value.
    shift
done

# Parse and check which JDK version we're testing upon.
version=$($TEST_JAVA_HOME/bin/java -version 2>&1 | head -1 | cut -d'"' -f2 | sed '/^1\./s///' | cut -d'.' -f1)

# ACCP requires a build JDK that exposes the javax.crypto.KEM API (JDK 21+ or a
# KEM-backported JDK 17 such as Corretto 17) to compile the ML-KEM Multi-Release
# overlay. Point JAVA_HOME at such a JDK if it is not already one; tests still run
# on TEST_JAVA_HOME, which may be an older runtime (JDK 8/11) that ACCP supports.
source tests/ci/select_build_jdk.sh
select_kem_capable_java_home

if (( "$version" <= "10" )); then
    ./gradlew \
        -DTEST_JAVA_HOME=$TEST_JAVA_HOME \
        -DTEST_JAVA_MAJOR_VERSION=$version \
        -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
        -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
        -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
        -DFIPS=$testing_fips \
        test_integration
    exit $?
fi

# Build with the KEM-capable JAVA_HOME selected above; integration tests run on
# TEST_JAVA_HOME (which may be an older JDK 11 runtime that ACCP still supports).
./gradlew \
    -DTEST_JAVA_HOME=$TEST_JAVA_HOME \
    -DTEST_JAVA_MAJOR_VERSION=$version \
    -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
    -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
    -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
    -DFIPS=$testing_fips \
    test_integration
