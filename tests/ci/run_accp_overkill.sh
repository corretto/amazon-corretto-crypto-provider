#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

echo "Testing ACCP overkill tests."

# dieharder_threads are not supported on ARM for now.
if [[ ("$(uname -p)" == 'aarch64'*) || ("$(uname -p)" == 'arm'*) ]]; then
	./gradlew test_extra_checks test_integration_extra_checks
else
	./gradlew test_extra_checks test_integration_extra_checks dieharder_threads
fi
