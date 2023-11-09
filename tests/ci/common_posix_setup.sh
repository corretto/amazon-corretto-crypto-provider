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
  if [[ $PLATFORM == "aarch64" ]]; then
    CPU_PART=$(grep -Po -m 1 'CPU part.*:\s\K.*' /proc/cpuinfo)
    NUM_CPU_PART=$(grep -c $CPU_PART /proc/cpuinfo)
    # Set capabilities via the static flags for valgrind tests.
    # This is because valgrind reports the instruction
    #   mrs %0, MIDR_EL1
    # which fetches the CPU part number, as illegal.
    # For some reason, valgrind also reports SHA512 instructions illegal,
    # so the SHA512 capability is not included below.
    VALGRIND_STATIC_CAP_FLAGS="-DOPENSSL_STATIC_ARMCAP -DOPENSSL_STATIC_ARMCAP_NEON"
    VALGRIND_STATIC_CAP_FLAGS+=" -DOPENSSL_STATIC_ARMCAP_AES -DOPENSSL_STATIC_ARMCAP_PMULL "
    VALGRIND_STATIC_CAP_FLAGS+=" -DOPENSSL_STATIC_ARMCAP_SHA1 -DOPENSSL_STATIC_ARMCAP_SHA256 "
    if [[ $NUM_CPU_PART == $NUM_CPU_THREADS ]] && [[ ${CPU_PART} =~ 0x[dD]40 ]]; then
      VALGRIND_STATIC_CAP_FLAGS+=" -DOPENSSL_STATIC_ARMCAP_SHA3 -DOPENSSL_STATIC_ARMCAP_NEOVERSE_V1"
    fi
  fi
fi

# Pick cmake3 if possible. We don't know of any OS that installs a cmake3
# executable that is not at least version 3.0.
if [[ -x "$(command -v cmake3)" ]] ; then
  CMAKE_COMMAND="cmake3"
else
  CMAKE_COMMAND="cmake"
fi

function run_build {
  local cflags=("$@")
  rm -rf "$BUILD_ROOT"
  mkdir -p "$BUILD_ROOT"
  cd "$BUILD_ROOT" || exit 1

  if [[ "${AWSLC_32BIT}" == "1" ]]; then
    cflags+=("-DCMAKE_TOOLCHAIN_FILE=${SRC_ROOT}/util/32-bit-toolchain.cmake")
  fi

  if [[ -x "$(command -v ninja)" ]]; then
    echo "Using Ninja build system (ninja)."
    BUILD_COMMAND="ninja"
    cflags+=(-GNinja)
  elif [[ -x "$(command -v ninja-build)" ]]; then
    echo "Using Ninja build system (ninja-build)."
    BUILD_COMMAND="ninja-build"
    cflags+=(-GNinja)
  else
    echo "Using Make."
    BUILD_COMMAND="make -j${NUM_CPU_THREADS}"
  fi

  ${CMAKE_COMMAND} "${cflags[@]}" "$SRC_ROOT"
  $BUILD_COMMAND
  cd "$SRC_ROOT"
}

function run_cmake_custom_target {
  $BUILD_COMMAND -C "$BUILD_ROOT" "$@"
}

function build_and_test {
  run_build "$@"
  run_cmake_custom_target 'run_tests'
}

function generate_symbols_file {
  # read_symbols.go currently only support static libraries
  if [ ! -f  "$BUILD_ROOT"/crypto/libcrypto.a ]; then
    echo "Static library not found: ${BUILD_ROOT}/crypto/libcrypto.a"
    exit 1
  fi

  go run "$SRC_ROOT"/util/read_symbols.go -out "$BUILD_ROOT"/symbols_crypto.txt "$BUILD_ROOT"/crypto/libcrypto.a
  go run "$SRC_ROOT"/util/read_symbols.go -out "$BUILD_ROOT"/symbols_ssl.txt "$BUILD_ROOT"/ssl/libssl.a

  # The $BUILD_ROOT gets deleted on each run. symbols.txt must be placed elsewhere.
  cat "$BUILD_ROOT"/symbols_crypto.txt  "$BUILD_ROOT"/symbols_ssl.txt >  "$SRC_ROOT"/symbols.txt
}


function verify_symbols_prefixed {
  go run "$SRC_ROOT"/util/read_symbols.go -out "$BUILD_ROOT"/symbols_final_crypto.txt "$BUILD_ROOT"/crypto/libcrypto.a
  go run "$SRC_ROOT"/util/read_symbols.go -out "$BUILD_ROOT"/symbols_final_ssl.txt "$BUILD_ROOT"/ssl/libssl.a
  # For grep's basic regular expression language the meta-characters (e.g. "?",
  # "|", etc.) are interpreted as literal characters. To keep their
  # meta-character semantics, they must be escaped with "\".
  # Deciphering the pattern "^_\?\(bignum\|curve25519_x25519\)":
  #  * "^": anchor at start of line.
  #  * "_\?": might contain underscore.
  #  * "\(bignum\|curve25519_x25519\)": match string of either "bignum" or "curve25519_x25519".
  # Recall that the option "-v" reverse the pattern matching. So, we are really
  # filtering out lines that contain either "bignum" or "curve25519_x25519".
  cat "$BUILD_ROOT"/symbols_final_crypto.txt  "$BUILD_ROOT"/symbols_final_ssl.txt | grep -v -e '^_\?\(bignum\|curve25519_x25519\)' >  "$SRC_ROOT"/symbols_final.txt
  # Now filter out every line that has the unique prefix $CUSTOM_PREFIX. If we
  # have any lines left, then some symbol(s) weren't prefixed, unexpectedly.
  if [ $(grep -c -v ${CUSTOM_PREFIX}  "$SRC_ROOT"/symbols_final.txt) -ne 0 ]; then
    echo "Symbol(s) missing prefix!"
    exit 1
  fi
}


function build_prefix_and_test {
  CUSTOM_PREFIX=aws_lc_1_1_0
  run_build "$@"
  generate_symbols_file
  run_build "$@" "-DBORINGSSL_PREFIX=${CUSTOM_PREFIX}" "-DBORINGSSL_PREFIX_SYMBOLS=${SRC_ROOT}/symbols.txt"
  verify_symbols_prefixed
  run_cmake_custom_target 'run_tests'
}

function fips_build_and_test {
  run_build "$@" -DFIPS=1
  # Upon completion of the build process. The module’s status can be verified by 'tool/bssl isfips'.
  # https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
  # FIPS mode is enabled when 'defined(BORINGSSL_FIPS) && !defined(OPENSSL_ASAN)'.
  # https://github.com/aws/aws-lc/blob/220e266d4e415cf0101388b89a2bd855e0e4e203/crypto/fipsmodule/is_fips.c#L22
  expect_fips_mode=1
  for build_flag in "$@"
  do
    if [[ "${build_flag}" == '-DASAN=1' ]]; then
      expect_fips_mode=0
      break
    fi
  done
  module_status=$("${BUILD_ROOT}/tool/bssl" isfips)
  [[ "${expect_fips_mode}" == "${module_status}" ]] || { echo >&2 "FIPS Mode validation failed."; exit 1; }
  # Run tests.
  run_cmake_custom_target 'run_tests'
  "${BUILD_ROOT}/util/fipstools/test_fips"
}

function build_and_test_valgrind {
  if [[ $PLATFORM == "aarch64" ]]; then
    run_build "$@" -DCMAKE_C_FLAGS="$VALGRIND_STATIC_CAP_FLAGS"
    run_cmake_custom_target 'run_tests_valgrind'

    # Disable all capabilities and run again
    # (We don't use the env. variable OPENSSL_armcap because it is currently
    #  restricted to the case of runtime discovery of capabilities
    #  in cpu_aarch64_linux.c)
    run_build "$@" -DCMAKE_C_FLAGS="-DOPENSSL_STATIC_ARMCAP"
    run_cmake_custom_target 'run_tests_valgrind'
  else
    run_build "$@"
    run_cmake_custom_target 'run_tests_valgrind'
  fi
}

function build_and_test_ssl_runner_valgrind {
  export AWS_LC_GO_TEST_TIMEOUT="60m"

  if [[ $PLATFORM == "aarch64" ]]; then
    run_build "$@" -DCMAKE_C_FLAGS="$VALGRIND_STATIC_CAP_FLAGS"
  else
    run_build "$@"
  fi
    run_cmake_custom_target 'run_ssl_runner_tests_valgrind'
}

function build_and_test_with_sde {
  run_build "$@"
  run_cmake_custom_target 'run_tests_with_sde'
}

function build_and_run_minimal_test {
  run_build "$@"
  run_cmake_custom_target 'run_minimal_tests'
}

# Install local build of AWS-LC for integration testing.
function aws_lc_build() {
  AWS_LC_DIR=${1}
  BUILD_FOLDER=${2}
  INSTALL_FOLDER=${3}

  echo "Building AWS-LC to ${BUILD_FOLDER} and installing to ${INSTALL_FOLDER} with CFlags "${@:4}""
  ${CMAKE_COMMAND} ${AWS_LC_DIR} -GNinja "-B${BUILD_FOLDER}" "-DCMAKE_INSTALL_PREFIX=${INSTALL_FOLDER}" "${@:4}"
  ninja -C ${BUILD_FOLDER} install
  ls -R ${INSTALL_FOLDER}
  rm -rf ${BUILD_FOLDER:?}/*
}

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
