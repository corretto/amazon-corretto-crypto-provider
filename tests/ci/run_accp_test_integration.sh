#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Assign the JAVA_HOME variable to the path. Otherwise, Ubuntu will
# default to the newest version of Java.
export PATH=$JAVA_HOME/bin:$PATH

if type -p java; then
	# Parse and check which Java version we're using.
    version=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | sed '/^1\./s///' | cut -d'.' -f1)

    # This flag is necessary in Java17+ for certain unit tests to
	# perform deep reflection on nonpublic members.
    if (( "$version" >= "17" )); then
        ./gradlew -DTEST_JAVA_MAJOR_VERSION=$version test_integration
    else
        ./gradlew test_integration
    fi
fi
