#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Testing non-FIPS is the default.
testing_fips=false
if [[ "${1}" == "--fips" ]]; then
	testing_fips=true
fi

echo "Testing ACCP dieharder tests."
./gradlew -DFIPS=$testing_fips dieharder
