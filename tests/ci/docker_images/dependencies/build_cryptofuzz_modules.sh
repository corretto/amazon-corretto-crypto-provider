#!/bin/bash
set -exo pipefail

function env {
  export "$1"="$2"
  echo "export ${1}=\"${2}\"" >> "${FUZZ_ROOT}/fuzz_env.sh"
}
# Recommended flags from https://github.com/guidovranken/cryptofuzz/blob/master/docs/building.md
# Remove-fsanitize=undefined which doesn't fail the build but creates additional noise in build output
export CFLAGS="-fsanitize=address,fuzzer-no-link -O2 -g -Wno-gnu-designator"
export CXXFLAGS="-fsanitize=address,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g"

# Setup base of Cryptofuzz
cd "$FUZZ_ROOT"
MODULES_ROOT="${FUZZ_ROOT}/modules"
git clone --depth 1 https://github.com/guidovranken/cryptofuzz.git
cd cryptofuzz
git rev-parse HEAD
CRYPTOFUZZ_SRC=$(pwd)
python3 gen_repository.py

# Setup Boost library
wget https://boostorg.jfrog.io/artifactory/main/release/1.83.0/source/boost_1_83_0.tar.gz
tar -xzf boost_1_83_0.tar.gz
BOOST_DIRECTORY=`realpath boost_1_83_0`
export CXXFLAGS="${CXXFLAGS} -I ${BOOST_DIRECTORY}"

mkdir "$MODULES_ROOT"
cd "$MODULES_ROOT"

# Setup the other crypto libraries for differential fuzzing

# Crypto++ https://github.com/guidovranken/cryptofuzz/blob/master/docs/cryptopp.md
cd "$MODULES_ROOT"
git clone --depth 1 https://github.com/weidai11/cryptopp.git
cd cryptopp/
git rev-parse HEAD
make libcryptopp.a -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
env LIBCRYPTOPP_A_PATH `realpath libcryptopp.a`
env CRYPTOPP_INCLUDE_PATH `realpath .`
cd "${CRYPTOFUZZ_SRC}/modules/cryptopp/"
make -j$(nproc)

# Extract the seed corpus, docker layers are already compressed so this won't use any more space and save time when running
cd "$FUZZ_ROOT"
unzip cryptofuzz_data.zip
rm cryptofuzz_data.zip
env CRYPTOFUZZ_SEED_CORPUS `realpath cryptofuzz_seed_corpus`
env CRYPTOFUZZ_DICT `realpath cryptofuzz-dict.txt`

# Save final common flags
env LINK_FLAGS ""
env CFLAGS "$CFLAGS"
env CXXFLAGS "$CXXFLAGS"
env CRYPTOFUZZ_SRC "$CRYPTOFUZZ_SRC"

# Prebuild the required libcpu_features to save time
cd "$CRYPTOFUZZ_SRC"
make third_party/cpu_features/build/libcpu_features.a
