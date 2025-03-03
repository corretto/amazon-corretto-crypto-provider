#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

testing_experimental_fips=false
testing_fips_self_test_failure_no_abort=false
testing_fips_test_break=false

# Testing non-FIPS is the default.
testing_fips=false
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
      testing_fips_self_test_failure_no_abort=true
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

# The JDK version should be least 10 for a regular ACCP build. We can
# still test on older versions with the TEST_JAVA_HOME property.
if (( "$version" <= "10" )); then
    ./gradlew \
        -DTEST_JAVA_HOME=$TEST_JAVA_HOME \
        -DTEST_JAVA_MAJOR_VERSION=$version \
        -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
        -DFIPS_SELF_TEST_FAILURE_NO_ABORT=$testing_fips_self_test_failure_no_abort \
        -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
        -DFIPS=$testing_fips \
        test_integration
    exit $?
fi

# Assign the JDK version we're testing as the system's default JDK and
# assign JAVA_HOME variable to the path. Otherwise, Ubuntu will
# default to the newest version of Java on the system.
export JAVA_HOME=$TEST_JAVA_HOME
export PATH=$JAVA_HOME/bin:$PATH

./gradlew \
    -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
    -DFIPS_SELF_TEST_FAILURE_NO_ABORT=$testing_fips_self_test_failure_no_abort \
    -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
    -DFIPS=$testing_fips \
    test_integration
