#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Testing non-FIPS is the default.
testing_fips=false
testing_experimental_fips=false
testing_fips_self_test_skip_abort=false
testing_fips_test_break=false

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
    *)
        echo "$1 is not supported."
        exit 1
        ;;
    esac
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
        -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
        -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
        -DFIPS=$testing_fips \
        -DLCOV_IGNORE=$lcov_ignore \
        coverage test
    exit $?
fi

# Assign the JDK version we're testing as the system's default JDK and
# assign JAVA_HOME variable to the path. Otherwise, Ubuntu will
# default to the newest version of Java on the system.
export JAVA_HOME=$TEST_JAVA_HOME
export PATH=$JAVA_HOME/bin:$PATH

# Since gradle upgrade to 8.13, Gradle macOS CI workflow fails with this error:
# "Expected a previously known directory snapshot at <truncated>/build/cmake/javadoc/AmazonCorrettoCryptoProvider
#  but got MissingFileSnapshot/AmazonCorrettoCryptoProvider"
# The referenced directory is the source folder for the 'javadoc' gradle task.
# The error happens because Gradle expects to have a previous known snapshot of the source directory but its missing.
# The actual directory exists. It likely an issue with Gradle's internal store of its snapshots.
# But this error happens only happens when 'release' task is executed first (which depends on both 'executeCmake' and 'javadoc' tasks)
# followed by any other task. But if any other task that depends on 'executeCmake' is executed first,
# then executing 'javadoc' doesn't seem to break the build when subsequent tasks are executed !!
#
# Note: Though 'release' is dependent on 'executeCmake', it will not be executed again as it will be considered 'up-to-date'

./gradlew \
    -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
    -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
    -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
    -DFIPS=$testing_fips \
    -DLCOV_IGNORE=$lcov_ignore \
    executeCmake

./gradlew \
    -DEXPERIMENTAL_FIPS=$testing_experimental_fips \
    -DFIPS_SELF_TEST_SKIP_ABORT=$testing_fips_self_test_skip_abort \
    -DALLOW_FIPS_TEST_BREAK=$testing_fips_test_break \
    -DFIPS=$testing_fips \
    -DLCOV_IGNORE=$lcov_ignore \
    release
