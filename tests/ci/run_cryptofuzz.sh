#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Sourcing these files check for environment variables which may be unset so wait to enable -u
source tests/ci/common_fuzz.sh
source "${FUZZ_ROOT}/fuzz_env.sh"
# After loading everything any undefined variables should fail the build
set -u

rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"

# Build ACCP, but skip the tests since that's covered by all the other CI
cd ${SRC_ROOT}
./gradlew -x check build
AWSLC_INSTALL_PATH=`realpath build/awslc/bin/`
export AWSLC_INCLUDE_PATH="${AWSLC_INSTALL_PATH}/include/"
export AWSLC_LIBRARY_PATH="${AWSLC_INSTALL_PATH}/lib64/"
export CXXFLAGS="$CXXFLAGS -I $AWSLC_INCLUDE_PATH"
export ACCP_JAR=`realpath build/lib/AmazonCorrettoCryptoProvider.jar`

# We run the Java module with ACCP as the JCE provider.
# This module uses OpenSSL symbols, so we provide those from AWS-LC to avoid symbol conflicts
# Java https://github.com/guidovranken/cryptofuzz/blob/master/docs/java.md
export JDK_PATH=${JAVA_HOME}
export LINK_FLAGS="${LINK_FLAGS} -L${JDK_PATH}/lib/server/ -ljvm -L${AWSLC_LIBRARY_PATH} -lcrypto"
export LINK_FLAGS="${LINK_FLAGS} -Wl,-rpath=${JDK_PATH}/lib/server/:${AWSLC_LIBRARY_PATH}"
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_JAVA -DJAVA_WITH_ECDSA -DCRYPTOFUZZ_ACCP"
cd "${CRYPTOFUZZ_SRC}/modules/java/"
make -j$(nproc)

# LSAN suppressions due to false positives
cd ${FUZZ_ROOT}
echo 'leak:libjvm.so' >> lsan.supp
echo 'leak:libz.so' >> lsan.supp
echo 'leak:libzip.so' >> lsan.supp
export LSAN_OPTIONS="suppressions=`realpath lsan.supp`"

# For cryptofuzz development only, override CRYPTOFUZZ_SRC with CUSTOM_CRYPTOFUZZ_REPO_DIR.
CUSTOM_CRYPTOFUZZ_REPO_DIR=''
if [[ -z "${CUSTOM_CRYPTOFUZZ_REPO_DIR}" ]]; then
  echo "CUSTOM_CRYPTOFUZZ_REPO_DIR is empty."
else
  export CRYPTOFUZZ_SRC="${CUSTOM_CRYPTOFUZZ_REPO_DIR}"
  cd "$CRYPTOFUZZ_SRC"
  # This step is to generate required header and cpp files.
  python3 gen_repository.py
fi

# Required linker flag set via this variable
export LIBFUZZER_LINK="-fsanitize=fuzzer"
# Explicitly disable OpenSSL module since it creates symbol conflicts
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"

# Build the overall cryptofuzz and generate_corpus binary
cd "$CRYPTOFUZZ_SRC"
rm -rf cryptofuzz
rm -rf generate_corpus
make "-j${NUM_CPU_THREADS}" cryptofuzz generate_corpus

# Common ACCP fuzzing setup, the cryptofuzz binary is in this folder so FUZZ_TEST_PATH=FUZZ_NAME
FUZZ_NAME="cryptofuzz"
FUZZ_TEST_PATH="${CRYPTOFUZZ_SRC}/${FUZZ_NAME}"
SRC_CORPUS="$CRYPTOFUZZ_SEED_CORPUS"

# For cryptofuzz development only, uncomment below code to generate new corpus.
# rm -rf "$CRYPTOFUZZ_SEED_CORPUS" && mkdir "$CRYPTOFUZZ_SEED_CORPUS"
# ./generate_corpus "$CRYPTOFUZZ_SEED_CORPUS"

# Perform the actual fuzzing. We want the total build time to be about 45 minutes:
# 5 minutes for building AWS-LC and Cryptofuzz
# 16 minutes (1000 seconds) of fuzzing
# 24 minutes of cleanup and merging in new inputs
TIME_FOR_EACH_FUZZ=${TIME_FOR_EACH_FUZZ:=1000}

# Some fuzz tests can take a while but still pass. This is a tradeoff: less false positive noise, but some inputs that take
# a long time could lead to a denial of service avenue. We're mostly interested in correctness and memory safety at this
# time so we're willing to take the fit on fuzz speed
FUZZ_TEST_TIMEOUT=${FUZZ_TEST_TIMEOUT:=30}

# Cryptofuzz lets us specify the operations and algorithms to fuzz
# We use this to narrow the fuzzing run to only what's supported by the Java/ACCP module rather than all of OpenSSL
FUZZ_TEST_ADDITIONAL_ARGS="--operations=Digest,HMAC,ECDSA_Verify"
FUZZ_TEST_ADDITIONAL_ARGS="${FUZZ_TEST_ADDITIONAL_ARGS} --digests=NULL,MD5,SHA1,SHA256,SHA384,SHA512"
FUZZ_TEST_ADDITIONAL_ARGS="${FUZZ_TEST_ADDITIONAL_ARGS} --curves=secp256r1,secp384r1"

# Call the common fuzzing logic
run_fuzz_test
