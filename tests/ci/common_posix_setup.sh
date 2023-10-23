# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

if [ -v CODEBUILD_SRC_DIR ]; then
  SRC_ROOT="$CODEBUILD_SRC_DIR"
else
  SRC_ROOT=$(pwd)
fi
echo "$SRC_ROOT"

cd ../
SYS_ROOT=$(pwd)
cd $SRC_ROOT

BUILD_ROOT="${SRC_ROOT}/test_build_dir"
echo "$BUILD_ROOT"

PLATFORM=$(uname -m)

NUM_CPU_THREADS=''
KERNEL_NAME=$(uname -s)
if [[ "${KERNEL_NAME}" == "Darwin" ]]; then
  # On MacOS, /proc/cpuinfo does not exist.
  NUM_CPU_THREADS=$(sysctl -n hw.ncpu)
else
  # Assume KERNEL_NAME is Linux.
  NUM_CPU_THREADS=$(grep -c ^processor /proc/cpuinfo)
fi

function print_executable_information {
  EXE_NAME=${1}
  EXE_ARGUMENT=${2}
  LABEL=${3}

  echo ""
  echo "${LABEL}:"
  if command -v ${EXE_NAME} &> /dev/null
  then
    ${EXE_NAME} ${EXE_ARGUMENT}
  else
    echo "${EXE_NAME} not found"
  fi
}

print_executable_information "cmake" "--version" "CMake version"
print_executable_information "cmake3" "--version" "CMake version (cmake3 executable)"
print_executable_information "go" "version" "Go version"
print_executable_information "perl" "--version" "Perl version"
# Ninja executable names are not uniform over operating systems
print_executable_information "ninja-build" "--version" "Ninja version (ninja-build executable)"
print_executable_information "ninja" "--version" "Ninja version (ninja executable)"
print_executable_information "gcc" "--version" "gcc version"
print_executable_information "g++" "--version" "g++ version"
print_executable_information "clang" "--version" "clang version"
print_executable_information "clang++" "--version" "clang++ version"
print_executable_information "cc" "--version" "cc version"
print_executable_information "c++" "--version" "c++ version"
print_executable_information "make" "--version" "Make version"
print_executable_information "rustup" "show" "Rust toolchain"
echo ""
echo "Operating system information:"
uname -a
echo ""
echo "Environment variables:"
env
