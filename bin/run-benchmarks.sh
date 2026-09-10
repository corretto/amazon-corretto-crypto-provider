#!/usr/bin/env bash

set -eux
set -o pipefail

CURRENT_PLATFORM="$(uname)"
TARGET_PLATFORM="${CURRENT_PLATFORM}"

function _usage() {
    echo "usage: ${0} [-p Linux|Darwin]"
    exit ${1:-1}
}

while getopts "a:p:h" opt; do
    case "$opt" in
        p) TARGET_PLATFORM=${OPTARG} ;;
        h) _usage; exit 0;;
        :) _usage "-${OPTARG} needs argument" ; exit 1 ;;
        \?) _usage "Unrecognized option -${OPTARG}" ; exit 1;;
    esac
done

# Corretto 17, not 11: the Gradle wrapper needs a JVM 17 or newer, and the build
# needs javax.crypto.KEM to compile the ML-KEM overlay. See Dockerfile.dev.
_install_dependencies() {
    if [[ $CURRENT_PLATFORM == "Linux" ]]; then
        sudo yum update -y
        sudo yum install -y \
            git \
            cmake3 \
            gradle \
            java-17-amazon-corretto \
            clang
    elif [[ $CURRENT_PLATFORM == "Darwin" ]]; then
        if ! command -v brew &>/dev/null; then
            echo "Installing homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew update
        brew tap homebrew/cask-versions
        brew update
        brew install \
            git \
            cmake \
            gradle
        local java_version='17'
        brew install --cask "corretto${java_version}"
        export JAVA_HOME="/Library/Java/JavaVirtualMachines/amazon-corretto-${java_version}.jdk/Contents/Home/"
    fi
}

_main() {
    ./gradlew cmake_clean jmh jmhReport
}

_install_dependencies
_main
