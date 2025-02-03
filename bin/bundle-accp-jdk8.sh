#!/bin/bash
set -e
set -x

# Use this script for JDKs 8. Please note that this script does not modify the security file,
# so one still needs to programmatically install ACCP.
#
# This script requires JAVA_HOME set properly.
#
# usage: ./bundle-accp-jdk8.sh 2.3.3 linux-x86_64

ACCP_VERSION=$1 # for example 2.3.3
ACCP_PLATFORM=$2 # for example linux-x86_64 or osx-aarch64
FIPS_EXTENSION=${3:""} # for FIPS, pass -FIPS
BUILD_DIR="$(pwd)/build"
TMP_DIR="$BUILD_DIR/private/tmp"
ACCP_PATH="$TMP_DIR/accp"
JDK_PATH="$JAVA_HOME"
JAVA_BIN="$JDK_PATH/bin"

function download_accp {
    wget -O "$ACCP_PATH/accp.jar" "https://repo1.maven.org/maven2/software/amazon/cryptools/AmazonCorrettoCryptoProvider${FIPS_EXTENSION}/${ACCP_VERSION}/AmazonCorrettoCryptoProvider${FIPS_EXTENSION}-${ACCP_VERSION}-${ACCP_PLATFORM}.jar"
}

function mk_all_dirs {
    clean_all_dirs
    mkdir -p "$ACCP_PATH"
}

function clean_all_dirs {
    rm -rf "$ACCP_PATH"
}

function repackage_jdk {
    # Repackage JDK
    cp "$ACCP_PATH/accp.jar" "$JDK_PATH/jre/lib/ext"
    echo "Integration completed."
}

function test_integration {
    pushd examples/gradle-kt-dsl > /dev/null
    ./gradlew -PuseBundledAccp -Dorg.gradle.java.home="$JDK_PATH" lib:test
    popd > /dev/null
}

function main {
    mk_all_dirs
    download_accp
    repackage_jdk
    clean_all_dirs
    test_integration
}

main
