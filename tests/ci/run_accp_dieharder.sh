#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Testing non-FIPS is the default.
testing_fips=false
while [[ $# -gt 0 ]]; do
    case ${1} in
    --fips)
      testing_fips=true
      ;;
    *)
      echo "${1} is not supported."
      exit 1
      ;;
    esac
    # Check next option -- key/value.
    shift
done

echo "Testing ACCP dieharder tests."
./gradlew -DFIPS=$testing_fips dieharder
