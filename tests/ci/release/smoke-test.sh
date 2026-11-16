#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Loads one platform jar from JAR_DIR as the JCA provider and runs the release smoke tests on the
# current JDK. The ML-KEM test needs the JDK 17 KEM API.
#
# Usage: smoke-test.sh JAR_DIR PLATFORM FIPS JDK_MAJOR
set -euo pipefail

jar_dir=$1
platform=$2
fips=$3
jdk=$4

here=$(cd "$(dirname "$0")" && pwd)
prefix=AmazonCorrettoCryptoProvider$([ "$fips" = true ] && echo -FIPS || true)
jar=$(ls "$jar_dir"/$prefix-[0-9]*-"$platform".jar)
version=$(basename "$jar" | sed -E "s/^$prefix-(.+)-$platform\.jar$/\1/")
classes=$(mktemp -d)

javac -cp "$jar" -d "$classes" "$here/ReleaseSmokeTest.java"
java -cp "$jar:$classes" ReleaseSmokeTest "$version" "$fips"
if [ "$jdk" -ge 17 ]; then
  javac -cp "$jar" -d "$classes" "$here/ReleaseSmokeTestMlKem.java"
  java -cp "$jar:$classes" ReleaseSmokeTestMlKem
fi
