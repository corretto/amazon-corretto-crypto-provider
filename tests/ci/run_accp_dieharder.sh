#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Dieharder tests are only supported on x86_64.
if [[ ("$(uname -p)" == 'x86_64'*) ]]; then
	echo "Testing ACCP dieharder tests."
	./gradlew dieharder
fi
