#!/bin/bash
set -e
set -x

# Use this script for JDKs 11+. For JDK 8, bundling requires copying the jar into lib/ext directory of JDK.
# Please note that this script does not modify the security file, so one still needs to programmatically
# install ACCP.
#
# This script requires JAVA_HOME set properly.
#
# usage: ./bundle-accp.sh 2.3.3 linux-x86_64

ACCP_VERSION=$1 # for example 2.3.3
ACCP_PLATFORM=$2 # for example linux-x86_64 or osx-aarch64
FIPS_EXTENSION=${3:""} # for FIPS, pass -FIPS
BUILD_DIR="$(pwd)/build"
TMP_DIR="$BUILD_DIR/private/tmp"
ACCP_PATH="$TMP_DIR/accp"
ACCP_JMOD_DIR="$TMP_DIR/accp_jmod"
CUSTOM_JDK_PATH="$TMP_DIR/customjdk"
JDK_PATH="$JAVA_HOME"
JAVA_BIN="$JDK_PATH/bin"

function download_accp {
    wget -O "$ACCP_PATH/accp.jar" "https://repo1.maven.org/maven2/software/amazon/cryptools/AmazonCorrettoCryptoProvider${FIPS_EXTENSION}/${ACCP_VERSION}/AmazonCorrettoCryptoProvider${FIPS_EXTENSION}-${ACCP_VERSION}-${ACCP_PLATFORM}.jar"
}

function mk_all_dirs {
    clean_all_dirs
    mkdir -p "$ACCP_PATH"
    mkdir -p "$ACCP_JMOD_DIR"
}

function clean_all_dirs {
    rm -rf "$CUSTOM_JDK_PATH"
    rm -rf "$ACCP_PATH"
    rm -rf "$ACCP_JMOD_DIR"
}

function create_native_jce_jmod {
    #This function creates a jmod from jar
    mkdir -p "$ACCP_JMOD_DIR/configs/com/amazon/corretto/crypto/provider/"
    cp "$ACCP_PATH/accp.jar" "$ACCP_JMOD_DIR/"

    #Extract jar and copy configs and libs
    pushd "$ACCP_JMOD_DIR" > /dev/null
    "$JAVA_BIN/jar" -xf "$ACCP_PATH/accp.jar"
    popd > /dev/null
    mv "$ACCP_JMOD_DIR/com/amazon/corretto/crypto/provider/version.properties" "$ACCP_JMOD_DIR/configs/com/amazon/corretto/crypto/provider/"

    #Create jmod
    "$JAVA_BIN/jmod" create --class-path "$ACCP_JMOD_DIR/accp.jar" --config "$ACCP_JMOD_DIR/configs" com.amazon.corretto.crypto.provider.jmod
    mv com.amazon.corretto.crypto.provider.jmod "$JDK_PATH/jmods/"
}

function repackage_jdk {
    # Repackage JDK
    JMOD_LIST=$(ls -1 $JDK_PATH/jmods | sed 's/.jmod$//g' |  tr '\n' ',' | sed 's/,$//')
    "$JAVA_BIN/jlink" -p "$JDK_PATH/jmods" --add-modules "$JMOD_LIST" --output "$CUSTOM_JDK_PATH"

    # Overwrite files on original JDK
    cp -rf $CUSTOM_JDK_PATH/* "$JDK_PATH/"
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
    create_native_jce_jmod
    repackage_jdk
    clean_all_dirs
    test_integration
}

main
