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

_install_dependencies() {
    if [[ $CURRENT_PLATFORM == "Linux" ]]; then
        sudo yum update -y
        sudo yum install -y \
            git \
            cmake3 \
            gradle \
            java-11-amazon-corretto \
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
        brew install --cask corretto11
                local java_version='11'
        brew install --cask "corretto${java_version}"
        export JAVA_HOME="/Library/Java/JavaVirtualMachines/amazon-corretto-${java_version}.jdk/Contents/Home/"
    fi
}

_main() {
    ./gradlew cmake_clean jmh jmhReport
}

_install_dependencies
_main
