#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

echo "Testing ACCP integration tests with corretto 11."
./gradlew test_integration

echo "Testing ACCP integration tests with corretto 8."
./gradlew -DTEST_JAVA_HOME=/usr/lib/jvm/java-1.8.0-amazon-corretto test_integration

echo "Testing ACCP integration tests with corretto 17."
./gradlew -DTEST_JAVA_HOME=/usr/lib/jvm/java-17-amazon-corretto -DTEST_JAVA_MAJOR_VERSION=17 test_integration
