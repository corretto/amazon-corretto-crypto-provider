# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)
project(AmazonCorrettoCryptoProvider)
include(CheckLibraryExists)
include(UseJava)
include(CheckCXXSourceCompiles)
include(CheckCXXCompilerFlag)

if (CMAKE_VERSION VERSION_GREATER 3.10)
  find_package(Java 10 REQUIRED)
else()
  # We must support old versions of cmake which do not understand modern versions of java.
  # Old CMAKE doesn't support JDK10 (because it stops offering javah). So, we cannot use find_package(java)
  # Instead, we'll manually set the variables we need.

  set(JAVA_BIN ${JAVA_HOME}/bin)
  set(Java_JAVA_EXECUTABLE ${JAVA_BIN}/java)
  set(Java_JAVAC_EXECUTABLE ${JAVA_BIN}/javac)
  set(Java_JAVADOC_EXECUTABLE ${JAVA_BIN}/javadoc)
  set(Java_IDLJ_EXECUTABLE ${JAVA_BIN}/idlj)
  set(Java_JAR_EXECUTABLE ${JAVA_BIN}/jar)
  set(Java_JARSIGNER_EXECUTABLE ${JAVA_BIN}/jarsigner)
  set(Java_IDLJ_EXECUTABLE ${JAVA_BIN}/idlj)
  set(Java_VERSION_STRING ${JAVA_MAJOR_VERSION}.${JAVA_MINOR_VERSION})
  set(Java_VERSION_MAJOR ${JAVA_MAJOR_VERSION})
  set(Java_VERSION_MINOR ${JAVA_MINOR_VERSION})
endif()

find_package(JNI REQUIRED)
include(FindOpenSSL)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(BUILD_CLASSPATH "" CACHE STRING "Classpath to JARs to be included at build time")
set(TEST_CLASSPATH "" CACHE STRING "Classpath to be included at test build and test execution time")
set(SIGNED_JAR "" CACHE STRING "Path to a pre-signed JAR file, to be used instead of compiling the java source")
set(DIEHARDER_EXECUTABLE "dieharder" CACHE STRING "Path to the dieharder executable")
set(ENABLE_NATIVE_TEST_HOOKS NO CACHE BOOL "Enable debugging hooks in the RNG. Disable for production use.")
set(TEST_DATA_DIR ${PROJECT_SOURCE_DIR}/test-data/ CACHE STRING "Path to directory containing test data")
set(ORIG_SRCROOT ${PROJECT_SOURCE_DIR} CACHE STRING "Path to root of original package")
set(PROVIDER_VERSION_STRING "" CACHE STRING "X.Y.Z formatted version of the provider")
set(FIPS NO CACHE BOOL "Determine if this build is for FIPS mode")
set(ALWAYS_ALLOW_EXTERNAL_LIB NO CACHE BOOL "Always permit tests to load ACCP shared objects from the library path")

if (USE_CLANG_TIDY)
    # https://releases.llvm.org/9.0.0/tools/clang/tools/extra/docs/clang-tidy/checks/list.html
    # https://clang.llvm.org/extra/clang-tidy/#suppressing-undesired-diagnostics
    # TODO: Make this enforcing with "-warnings-as-errors=*;" once we're happy with the state
    set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-checks=-*")
    # Categories we want
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},bugprone-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},cert-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},cppcoreguidelines-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},clang-analyzer-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},performance-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},portability-*)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},readability-*)

    # Things we don't want
    # We must use reinterpret cast to move things across the JNI boundary
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},-cppcoreguidelines-pro-type-reinterpret-cast)
    # We intentionally omit the parameters for jclass
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},-readability-named-parameter)
    # We target older styles of C++. We can revisit these after checking all build chains
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_CXX_CLANG_TIDY},-cppcoreguidelines-macro-usage)
    # Anything referencing gsl:: (Guidelines support library) is too new for us
endif()

if (NOT DEFINED JACOCO_AGENT_JAR)
   set(JACOCO_AGENT_JAR ${JACOCO_ROOT}/jacocoagent.jar)
endif()

if (NOT DEFINED TEST_JAVA_HOME)
  set(TEST_JAVA_EXECUTABLE ${Java_JAVA_EXECUTABLE})
  set(TEST_JAVA_MAJOR_VERSION ${Java_VERSION_MAJOR})
else()
  set(TEST_JAVA_EXECUTABLE ${TEST_JAVA_HOME}/bin/java)
endif()

# Translate from the java colon-delimited paths to cmake ';' delimited lists
string(REPLACE ":" ";" BUILD_CLASSPATH_LIST "${BUILD_CLASSPATH}")
string(REPLACE ":" ";" TEST_CLASSPATH_LIST "${TEST_CLASSPATH}")

# Needed as we abuse some of the test compile macros to test shared lib links
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# CMake's default RPath handling includes the full build directory path, which isn't needed. Turn it off.
set(CMAKE_SKIP_RPATH TRUE)
set(GENERATE_HASHERS ${CMAKE_CURRENT_SOURCE_DIR}/build-tools/bin/generate-java-hash-spi)
set(GENERATED_JAVA_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated-java/com/amazon/corretto/crypto/provider)
set(JNI_HEADER_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated-include)

## Query our SPI generator to find out what output files it intends to generate.
## Note that this query runs at configure time...
execute_process(
    COMMAND ${GENERATE_HASHERS} list ${CMAKE_CURRENT_SOURCE_DIR} ${GENERATED_JAVA_DIR}
    OUTPUT_VARIABLE GENERATED_JAVA_SRC
    RESULT_VARIABLE RETURN_VALUE
    )

if (NOT RETURN_VALUE EQUAL 0)
    message(FATAL_ERROR "Failed to list generated hash function types")
endif()

# This forces cmake to rerun if the generate script itself changes (and
# therefore the list of files generated might change). Unfortunately this
# dummy-file bit seems to be the supported way to do this, see e.g.
# https://cmake.org/pipermail/cmake/2010-November/040978.html

# The actual effect of this line is to do some variable substitutions in
# ${GENERATE_HASHERS} and write the output to the dummy-file, and this action
# results in re-invoking cmake to perform this substitution.

CONFIGURE_FILE(${GENERATE_HASHERS} ${CMAKE_CURRENT_BINARY_DIR}/dummy-file)

set(VERSION_PROPERTIES_FILE ${GENERATED_JAVA_DIR}/version.properties)

add_custom_command(
    OUTPUT ${VERSION_PROPERTIES_FILE}
    COMMAND ${CMAKE_COMMAND} -E echo versionStr=${PROVIDER_VERSION_STRING} > ${VERSION_PROPERTIES_FILE}
    COMMENT "Generation version properties file"
)

add_custom_command(
    COMMAND ${GENERATE_HASHERS} generate ${CMAKE_CURRENT_SOURCE_DIR} ${GENERATED_JAVA_DIR}
    DEPENDS ${GENERATE_HASHERS}
    OUTPUT ${GENERATED_JAVA_SRC}
    COMMENT "Generating hash function SPI classes..."
    )

# NOTE: CMake introduced the CONFIGURE_DEPENDS feature in 3.12, so condition
#       its use on CMake version. If the feature is not available, you may need
#       to `touch CMakeLists.txt` after adding/removing files for them to be
#       detected by CMake.
if (${CMAKE_VERSION} VERSION_LESS "3.12.0")
    file(GLOB ACCP_SRC "src/com/amazon/corretto/crypto/provider/*.java")
else()
    file(GLOB ACCP_SRC CONFIGURE_DEPENDS "src/com/amazon/corretto/crypto/provider/*.java")
endif()
set(ACCP_SRC ${ACCP_SRC} ${GENERATED_JAVA_SRC})

set(BASE_JAVA_COMPILE_FLAGS ${CMAKE_JAVA_COMPILE_FLAGS} -h "${JNI_HEADER_DIR}" -Werror -Xlint)

# Java targets defined here are compiled for Java supporting modules
set(CMAKE_JAVA_COMPILE_FLAGS ${BASE_JAVA_COMPILE_FLAGS} --release 9)

set(ACCP_JAR "${CMAKE_CURRENT_BINARY_DIR}/AmazonCorrettoCryptoProvider.jar")
set(ACCP_JAR_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/AmazonCorrettoCryptoProvider-sources.jar")

add_jar(
    module-jar
    SOURCES ${ACCP_SRC}
        src/module-info.java
    INCLUDE_JARS ${BUILD_CLASSPATH_LIST}
)

create_javadoc(
    AmazonCorrettoCryptoProvider
    FILES ${ACCP_SRC}
    WINDOWTITLE "Amazon Corretto Crypto Provider"
    DOCTITLE "<h1>Amazon Corretto Crypto Provider</h1>"
    AUTHOR FALSE
    USE TRUE
    VERSION TRUE
)

add_custom_target(javadoc DEPENDS ${JNI_HEADER_DIR}/generated-headers.h ${GENERATED_JAVA_SRC} AmazonCorrettoCryptoProvider_javadoc)

# All subsequent Java targets are compatible with Java 8
set(CMAKE_JAVA_COMPILE_FLAGS ${BASE_JAVA_COMPILE_FLAGS} --release 8)

# Add a JAR target. We can't add resources here (as discussed below) so we'll
# build a temporary one first.

add_jar(
    code-only-jar
    SOURCES ${ACCP_SRC}
    INCLUDE_JARS ${BUILD_CLASSPATH_LIST}
)

if (SIGNED_JAR)
# Just copy the JAR in
    add_custom_command(
        OUTPUT ${ACCP_JAR}
        COMMAND ${CMAKE_COMMAND} -E copy ${SIGNED_JAR} ${ACCP_JAR}
        COMMAND ${CMAKE_COMMAND} -E echo Copied ${SIGNED_JAR} to ${ACCP_JAR}
        COMMAND ${CMAKE_COMMAND} -E copy ${OPENSSL_CRYPTO_LIBRARY} $<TARGET_FILE_DIR:amazonCorrettoCryptoProvider>
    )
else()
# CMake's UseJar doesn't let us control the paths that resource files are
# placed at - if we list them, they'll be stored based on their path relative
# to CMAKE_CURRENT_SOURCE_DIR, so we'll need to manually add them in. We let
# CMake build the class files above, then copy the JAR and add some additional
# files to it.
    set(ACCP_JAR_TMP "${CMAKE_CURRENT_BINARY_DIR}/AmazonCorrettoCryptoProvider.tmp.jar")
    add_custom_command(
        OUTPUT ${ACCP_JAR}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:code-only-jar,JAR_FILE> ${ACCP_JAR_TMP}
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${ACCP_JAR_TMP}/com/amazon/corretto/crypto/provider/test
        COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_TMP} -C ${CMAKE_CURRENT_SOURCE_DIR}/extra-jar-files .
        COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_TMP} -C $<TARGET_PROPERTY:module-jar,CLASSDIR> module-info.class
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/tmplib/com/amazon/corretto/crypto/provider/
        COMMAND ${CMAKE_COMMAND} -E copy ${OPENSSL_CRYPTO_LIBRARY} $<TARGET_FILE_DIR:amazonCorrettoCryptoProvider>
        COMMAND ${CMAKE_COMMAND} -E copy ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_CURRENT_BINARY_DIR}/tmplib/com/amazon/corretto/crypto/provider/
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:amazonCorrettoCryptoProvider> ${CMAKE_CURRENT_BINARY_DIR}/tmplib/com/amazon/corretto/crypto/provider/
        COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_TMP} -C ${CMAKE_CURRENT_BINARY_DIR}/tmplib/ com/amazon/corretto/crypto/provider/
        COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_TMP} -C ${CMAKE_CURRENT_BINARY_DIR}/generated-java/ com/amazon/corretto/crypto/provider/version.properties
        COMMAND ${CMAKE_COMMAND} -E copy ${ACCP_JAR_TMP} ${ACCP_JAR}
        DEPENDS code-only-jar module-jar ${VERSION_PROPERTIES_FILE}
    )
endif()

add_custom_target(accp-jar ALL DEPENDS ${ACCP_JAR})

# Attach the JAR_FILE property to our custom jar target; this allows add_jar
# later on to recognize this target as a JAR target, and handle classpath
# dependencies appropriately.
set_property(TARGET accp-jar PROPERTY JAR_FILE ${ACCP_JAR})

# Generate a combined headers file; currently we assume all headers are in a
# single file on the C++ side, but javac -h creates a separate header for each
# class.  Arguably, we should include the specific headers we need only, but
# that's a later refactor.

ADD_CUSTOM_COMMAND(
    OUTPUT ${JNI_HEADER_DIR}/generated-headers.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build-tools/bin/generate-omni-header ${JNI_HEADER_DIR}
# Note that we still build the code-only-jar even if we're using the signed jar; this is
# primarily to generate java headers (generating headers via javah from binary classfiles is
# deprecated starting in Java 9). We depend on tests-code-jar because that generates headers
# we need for some test code.
    DEPENDS code-only-jar tests-code-jar
    )

### Native library configuration
include_directories(${OPENSSL_INCLUDE_DIR} ${JNI_INCLUDE_DIRS} ${JNI_HEADER_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/cpp)

add_library(
    amazonCorrettoCryptoProvider SHARED
        csrc/aes_gcm.cpp
        csrc/agreement.cpp
        csrc/bn.cpp
        csrc/buffer.cpp
        csrc/ec_gen.cpp
        csrc/ec_utils.cpp
        csrc/env.cpp
        csrc/hmac.cpp
        csrc/keyutils.cpp
        csrc/java_evp_keys.cpp
        csrc/libcrypto_rng.cpp
        csrc/loader.cpp
        csrc/md5.cpp
        csrc/rsa_cipher.cpp
        csrc/rsa_gen.cpp
        csrc/sha1.cpp
        csrc/sha256.cpp
        csrc/sha384.cpp
        csrc/sha512.cpp
        csrc/sign.cpp
        csrc/testhooks.cpp
        csrc/util.cpp
        csrc/util_class.cpp
        ${JNI_HEADER_DIR}/generated-headers.h
)

# We MUST set ACCP's RPATH to "$ORIGIN" so that the runtime dynamic loader will look in the same directory as ACCP for
# any shared library dependencies BEFORE looking for a system-installed depencencies (such as libcrypto). If RPath is
# not set, the loader may attempt to load an incompatible system-installed libcrypto and cause runtime crashes.
set_target_properties(amazonCorrettoCryptoProvider PROPERTIES LINK_FLAGS "-Wl,-rpath,\$ORIGIN")

add_custom_command(
    OUTPUT ${ACCP_JAR_SOURCE}
    COMMAND ${Java_JAR_EXECUTABLE} cf ${ACCP_JAR_SOURCE} -C ${CMAKE_CURRENT_SOURCE_DIR}/src .
    COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_SOURCE} -C ${CMAKE_CURRENT_SOURCE_DIR} csrc
    COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_SOURCE} -C ${CMAKE_CURRENT_SOURCE_DIR}/extra-jar-files com/amazon/corretto/crypto/provider/testdata
    COMMAND ${Java_JAR_EXECUTABLE} uf ${ACCP_JAR_SOURCE} -C ${CMAKE_CURRENT_BINARY_DIR}/generated-java/ .
    DEPENDS ${GENERATED_JAVA_SRC}
)

add_custom_target(accp-jar-source DEPENDS ${ACCP_JAR_SOURCE})

if(ENABLE_NATIVE_TEST_HOOKS)
  add_executable(test_keyutils EXCLUDE_FROM_ALL
        csrc/test_keyutils.cpp
    )
    set_target_properties(test_keyutils PROPERTIES LINK_FLAGS "-Wl,-rpath,\$ORIGIN")
    target_link_libraries(test_keyutils ${OPENSSL_CRYPTO_LIBRARY})
    target_link_libraries(test_keyutils amazonCorrettoCryptoProvider)
endif()

#### Start of feature tests

## First, figure out how best to link against openssl
set(OLD_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")

# This macro helps us perform tests that are not supported through the
# generic CHECK_CXX_COMPILER_FLAG mechanism. Specifically, these result
# in building certain targets on the project under the CMake/trycompile
# directory in the source tree. This is needed because there's no built-in
# mechanism for specifically testing for linker flag support on shared object
# targets.
#
# Usage: CHECK_CUSTOM_TRY_COMPILE(cached_flag_variable_name target_name [-DVAR:TYPE=value ...])
macro(CHECK_CUSTOM_TRY_COMPILE var target)
    if(NOT DEFINED "${var}")
        message(STATUS "Performing test ${var}...")

# Clean up any stray temp directory before we trycompile; otherwise we might
# get a false positive result due to the target being built already

        file(REMOVE_RECURSE ${CMAKE_CURRENT_BINARY_DIR}/try_compile_tmp/${var})

        try_compile(${var}
            ${CMAKE_CURRENT_BINARY_DIR}/try_compile_tmp/${var}
            ${CMAKE_CURRENT_SOURCE_DIR}/CMake/trycompile
            TryCompile ${target}
            CMAKE_FLAGS
                -DLINK_LIBS:STRING=${OPENSSL_CRYPTO_LIBRARY}
                -DOPENSSL_INCLUDE_DIR:STRING=${OPENSSL_INCLUDE_DIR}
                ${ARGN}
        )

        if(${var})
            message(STATUS "Performing test ${var} - Success")
        else()
            message(STATUS "Performing test ${var} - Failed")
        endif()
    endif()
endmacro(CHECK_CUSTOM_TRY_COMPILE)

# Macro to check and enable if supported a CXX compiler flag
macro(CHECK_ENABLE_CXX_FLAG var flags)
    CHECK_CXX_COMPILER_FLAG("${flags}" ${var})
    if(${var})
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flags}")
    endif()
endmacro()

# Linking openssl may require -ldl and/or -lm
CHECK_LIBRARY_EXISTS(dl "dlopen" "" HAVE_LIBDL)
CHECK_LIBRARY_EXISTS(m "sqrt" "" HAVE_LIBM)

if(HAVE_LIBDL)
    target_link_libraries(amazonCorrettoCryptoProvider dl)
endif()

if(HAVE_LIBM)
    target_link_libraries(amazonCorrettoCryptoProvider m)
endif()

# Enable language feature flags first, as they impact later feature tests
CHECK_ENABLE_CXX_FLAG(HAVE_CXX_11 "--std=c++11")

CHECK_CXX_SOURCE_COMPILES("int main() __attribute__((cold)) {return 0;}" HAVE_ATTR_COLD)
CHECK_CXX_SOURCE_COMPILES("int main() __attribute__((noreturn)) {return 0;}" HAVE_ATTR_NORETURN)
CHECK_CXX_SOURCE_COMPILES("int main() __attribute__((always_inline)) {return 0;}" HAVE_ATTR_ALWAYS_INLINE)
CHECK_CXX_SOURCE_COMPILES("int main() __attribute__((noinline)) {return 0;}" HAVE_ATTR_NOINLINE)
# getentropy is in unistd.h on linux
CHECK_CXX_SOURCE_COMPILES("
#define _DEFAULT_SOURCE
#include <unistd.h>

int main() {
    int foo;
    getentropy(&foo, sizeof(foo));
    return 0;
}" HAVE_GETENTROPY)
# ... and in sys/random on BSD/darwin
CHECK_CXX_SOURCE_COMPILES("
#define _DEFAULT_SOURCE
// OSX bug - sys/random.h is missing some #includes needed for macros
// it uses internally. Pull in unistd.h to try to work around this.
#include <unistd.h>
#include <sys/random.h>

int main() {
    int foo;
    getentropy(&foo, sizeof(foo));
    return 0;
}" HAVE_GETENTROPY_IN_SYSRANDOM)

CHECK_CXX_SOURCE_COMPILES("
#include <execinfo.h>
#include <dlfcn.h>
#include <cxxabi.h>

int main() {
    Dl_info info;
    (void)info.dli_fname;
    (void)info.dli_sname;
    (void)info.dli_saddr;
    (void)&dladdr;

    backtrace(NULL, 1);
    abi::__cxa_demangle(NULL, NULL, NULL, NULL);
    return 0;
}
" HAVE_BACKTRACE_APIS)
# Some versions of GCC claim CXX11 compliance but do not fully implement <type_traits>
CHECK_CXX_SOURCE_COMPILES("
#include <type_traits>

static_assert(std::is_trivially_copyable<int>::value,
    \"int should be trivally copyable\");

int main() { return 0; }
" HAVE_IS_TRIVIALLY_COPYABLE)
CHECK_CXX_SOURCE_COMPILES("
#include <type_traits>

static_assert(std::is_trivially_destructable<int>::value,
    \"int should be trivally destructable\");

int main() { return 0; }
" HAVE_IS_TRIVIALLY_DESTRUCTABLE)

if(${HAVE_BACKTRACE_APIS})
    if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(BACKTRACE_DEFAULT ON)
    endif()
endif()
option(BACKTRACE_ON_EXCEPTION "Enable backtraces in C++-originated exceptions" BACKTRACE_DEFAULT)

CHECK_CXX_SOURCE_COMPILES("
int main(int, char **) noexcept {}
" HAVE_NOEXCEPT)

set(CMAKE_REQUIRED_FLAGS "${OLD_CMAKE_REQUIRED_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${OLD_CMAKE_EXE_LINKER_FLAGS}")

# Miscellaneous linker flag tests. Unfortunately cmake doesn't have built-in
# functionality for a linker flag test, so we have to roll our own.

# This function will test if a linker flag is supported, and if it is, add it to
# ${PROBED_LINKER_FLAGS}. 'var' should be a unique cache variable name to store the
# flag-supported test result.
macro(CHECK_LINKER_FLAG_SUPPORT var flags)
    CHECK_CUSTOM_TRY_COMPILE(${var} empty -DLINK_FLAGS:STRING=${flags})

    if(${var})
        MESSAGE(STATUS "Using linker flags ${flags}")
        set(PROBED_LINKED_FLAGS "${PROBED_LINKED_FLAGS} ${flags}")
    endif()
endmacro(CHECK_LINKER_FLAG_SUPPORT)

# When test hooks are enabled we need to expose a bunch of internal symbols for the tests to poke at.
if(NOT ENABLE_NATIVE_TEST_HOOKS)
# This version script attempts to hide the openssl symbols (and any other
# internal symbols) from the exports table.
    CHECK_LINKER_FLAG_SUPPORT(USE_VERSION_SCRIPT "-Wl,--version-script -Wl,${CMAKE_CURRENT_SOURCE_DIR}/final-link.version")

# This does the same thing as the version script, but works on Darwin platforms
    CHECK_LINKER_FLAG_SUPPORT(USE_EXPORTED_SYMBOL "-Wl,-exported_symbol '-Wl,_Java_*' -Wl,-exported_symbol '-Wl,_JNI_*'")
endif()

# Attempt to drop unused sections; the idea here is to exclude unreferenced
# parts of openssl in the final library
CHECK_LINKER_FLAG_SUPPORT(USE_GC_SECTIONS "-Wl,--gc-sections")

# Mark that our library is compatible with non-executable stack segments.
# Otherwise, on linux, loading our library will mark the stack as executable.
CHECK_LINKER_FLAG_SUPPORT(USE_NOEXECSTACK "-Wl,-z -Wl,noexecstack")

### CXX flag tests

CHECK_ENABLE_CXX_FLAG(CXX_FLAG_WALL -Wall)
CHECK_ENABLE_CXX_FLAG(CXX_FLAG_WUNINIT -Wuninitialized)
CHECK_ENABLE_CXX_FLAG(CXX_FLAG_WERROR -Werror)
# We need C++11 or higher for 'long long' with -pedantic
CHECK_ENABLE_CXX_FLAG(CXX_FLAG_CXX11 --std=c++11)
if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
# This breaks backtraces, so only enable it in release mode
    CHECK_ENABLE_CXX_FLAG(CXX_FLAG_FOMITFP -fomit-frame-pointer)
endif()
if(NOT CXX_FLAG_CXX11)
# Maybe the old name will work? c++0x is a deprecated name but if we're on an old compiler we need to use it
    CHECK_ENABLE_CXX_FLAG(CXX_FLAG_CXX0x --std=c++0x)
# On gcc4.1, we get "cc1plus: warning: -Wuninitialized is not supported without -O" if this isn't added.
    CHECK_ENABLE_CXX_FLAG(CXX_FLAG_TEST -O)
endif()

if(CXX_FLAG_CXX11 OR CXX_FLAG_CXX0x)
# 'long long' is not supported before C++11, so don't enable -pedantic
# (which will warn on using long long at unsupported language levels)
# unless we have a new enough C++ version available
    CHECK_ENABLE_CXX_FLAG(CXX_FLAG_PEDANTIC -pedantic)
endif()

option(COVERAGE "Enable code coverage instrumentation" OFF)
if(COVERAGE)
    CHECK_CUSTOM_TRY_COMPILE(CXX_FLAG_COVERAGE coverage)
    if(NOT CXX_FLAG_COVERAGE)
        message(FATAL_ERROR "C++ compiler does not support coverage instrumentation")
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
# Disable assert()s. This avoids having unreachable assert branches pollute our branch coverage.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
endif()

### End feature tests - add our probed flags to the library link invocation

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
    # This enables expensive test-only assertions
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DEXTRA_TEST_ASSERT")
endif()

# Pass in provider version
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPROVIDER_VERSION_STRING=${PROVIDER_VERSION_STRING}")

# CMake disallows leading or trailing whitespace here, but our concatenations will
# leave us with leading whitespace, so strip it off first.
string(STRIP "${PROBED_LINKED_FLAGS}" PROBED_LINKED_FLAGS)
MESSAGE(STATUS "probed flags ${PROBED_LINKED_FLAGS}")
target_link_libraries(amazonCorrettoCryptoProvider ${PROBED_LINKED_FLAGS})

# Add pthread support
target_link_libraries(amazonCorrettoCryptoProvider Threads::Threads)

# Take a dependency on our libcrypto.so file
target_link_libraries(amazonCorrettoCryptoProvider ${OPENSSL_CRYPTO_LIBRARY})

# NOTE: CMake introduced the CONFIGURE_DEPENDS feature in 3.12, so condition
#       its use on CMake version. If the feature is not available, you may need
#       to `touch CMakeLists.txt` after adding/removing files for them to be
#       detected by CMake.
if (${CMAKE_VERSION} VERSION_LESS "3.12.0")
    file(GLOB_RECURSE ACCP_TEST_SRC "tst/com/amazon/corretto/crypto/provider/*.java")
else()
    file(GLOB_RECURSE ACCP_TEST_SRC CONFIGURE_DEPENDS "tst/com/amazon/corretto/crypto/provider/*.java")
endif()


## Tests
add_jar(
    tests-code-jar
    SOURCES ${ACCP_TEST_SRC}
    INCLUDE_JARS ${TEST_CLASSPATH_LIST} code-only-jar
)
set_target_properties(tests-code-jar PROPERTIES EXCLUDE_FROM_ALL 1)

# Our tests have some custom resources they rely upon as well. We'll just bundle the whole tests directory
# to make this easy.
set(TESTS_JAR "${CMAKE_CURRENT_BINARY_DIR}/tests.jar")
add_custom_command(
    OUTPUT ${TESTS_JAR}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:tests-code-jar,JAR_FILE> ${TESTS_JAR}.tmp.jar
    COMMAND ${Java_JAR_EXECUTABLE} uf ${TESTS_JAR}.tmp.jar -C ${CMAKE_CURRENT_SOURCE_DIR}/tst .
    COMMAND ${CMAKE_COMMAND} -E copy ${TESTS_JAR}.tmp.jar ${TESTS_JAR}
    DEPENDS tests-code-jar
)
add_custom_target(tests-jar DEPENDS ${TESTS_JAR})
set_property(TARGET tests-jar PROPERTY JAR_FILE ${TESTS_JAR})

# These flags are necessary in Java17+ in order for certain unit tests to
# perform deep reflection on nonpublic members
if (TEST_JAVA_MAJOR_VERSION VERSION_GREATER_EQUAL 17)
  set(TEST_ADD_OPENS
    --add-opens java.base/javax.crypto=ALL-UNNAMED
    --add-opens java.base/java.lang.invoke=ALL-UNNAMED
    --add-opens java.base/java.security=ALL-UNNAMED
    --add-exports jdk.crypto.ec/sun.security.ec=java.base
    )
endif()

set(COVERAGE_ARGUMENTS
    -javaagent:${JACOCO_AGENT_JAR}=destfile=coverage/jacoco.exec,classdumpdir=coverage/classes
)

if(FIPS)
    set(TEST_FIPS_PROPERTY "-DFIPS=true")
else()
    set(TEST_FIPS_PROPERTY "-DFIPS=false")
endif()

if(ALWAYS_ALLOW_EXTERNAL_LIB)
    set(EXTERNAL_LIB_PROPERTY "-Djava.library.path=$<TARGET_FILE_DIR:amazonCorrettoCryptoProvider>")
endif()

set(TEST_RUNNER_ARGUMENTS
    ${COVERAGE_ARGUMENTS}
    ${TEST_ADD_OPENS}
    ${TEST_FIPS_PROPERTY}
    ${EXTERNAL_LIB_PROPERTY}
    -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
    -Dtest.data.dir=${TEST_DATA_DIR}
    -Djunit.jupiter.execution.parallel.enabled=true
    -Djunit.jupiter.execution.parallel.mode.default=concurrent
    -Djunit.jupiter.execution.parallel.mode.classes.default=concurrent
    -XX:+HeapDumpOnOutOfMemoryError
    ${TEST_JAVA_ARGS}
    -jar ${TEST_RUNNER_JAR}
    -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
    --details=summary
    --details-theme=ascii
    --fail-if-no-tests
)

if("$ENV{ACCP_TEST_COLOR}" STREQUAL "false")
    set(TEST_RUNNER_ARGUMENTS ${TEST_RUNNER_ARGUMENTS} --disable-ansi-colors)
endif()

## Note: We can't use the 'test' target as it's reserved by cmake's own test subsystem.
add_custom_target(check-junit
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${TEST_RUNNER_ARGUMENTS}
        --reports-dir=unit-tests
        --select-package=com.amazon.corretto.crypto.provider.test
        --exclude-package=com.amazon.corretto.crypto.provider.test.integration
        --exclude-classname=com.amazon.corretto.crypto.provider.test.SecurityManagerTest

    DEPENDS accp-jar tests-jar)

if (DEFINED SINGLE_TEST)
    add_custom_target(check-junit-single
        COMMAND ${TEST_JAVA_EXECUTABLE}
            ${TEST_RUNNER_ARGUMENTS}
            --select-class=${SINGLE_TEST}

        DEPENDS accp-jar tests-jar)
endif() # SINGLE_TEST

add_custom_target(check-junit-SecurityManager
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${TEST_RUNNER_ARGUMENTS}
        --select-class=com.amazon.corretto.crypto.provider.test.AesTest # Force loading ciphers
        --select-class=com.amazon.corretto.crypto.provider.test.SHA1Test # Force loading digests
        --select-class=com.amazon.corretto.crypto.provider.test.SecurityManagerTest

    DEPENDS accp-jar tests-jar)

add_custom_target(check-junit-extra-checks
    COMMAND ${TEST_JAVA_EXECUTABLE}
        -Dcom.amazon.corretto.crypto.provider.extrachecks=ALL
        -Dcom.amazon.corretto.crypto.provider.debug=ALL
        ${TEST_RUNNER_ARGUMENTS}
        --select-package=com.amazon.corretto.crypto.provider.test
        --exclude-package=com.amazon.corretto.crypto.provider.test.integration
        --exclude-classname=com.amazon.corretto.crypto.provider.test.SecurityManagerTest

    DEPENDS accp-jar tests-jar)

add_custom_target(check-recursive-init
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${COVERAGE_ARGUMENTS}
        ${TEST_FIPS_PROPERTY}
        -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
        -Dtest.data.dir=${TEST_DATA_DIR}
        ${TEST_JAVA_ARGS}
        com.amazon.corretto.crypto.provider.test.RecursiveInitializationTest

    DEPENDS accp-jar tests-jar)

if (TEST_JAVA_MAJOR_VERSION VERSION_GREATER 11)
    set(INSTALL_PROPERTY_FILE ${ORIG_SRCROOT}/etc/amazon-corretto-crypto-provider-jdk15.security)
else()
    set(INSTALL_PROPERTY_FILE ${ORIG_SRCROOT}/etc/amazon-corretto-crypto-provider.security)
endif()

add_custom_target(check-install-via-properties
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${COVERAGE_ARGUMENTS}
        ${TEST_FIPS_PROPERTY}
        -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
        -Dtest.data.dir=${TEST_DATA_DIR}
        -Djava.security.properties=${INSTALL_PROPERTY_FILE}
        ${TEST_JAVA_ARGS}
        com.amazon.corretto.crypto.provider.test.SecurityPropertyTester

    DEPENDS accp-jar tests-jar)

add_custom_target(check-external-lib
    # Unfortunately we do not have a way to know where the library is loaded from.
    # So this test just proves that requesting the external lib does not break things
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${COVERAGE_ARGUMENTS}
        ${TEST_FIPS_PROPERTY}
        -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        # Since this tests external loading we always provide this property
        -Djava.library.path=$<TARGET_FILE_DIR:amazonCorrettoCryptoProvider>
        -Dcom.amazon.corretto.crypto.provider.useExternalLib=true
        -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
        -Dtest.data.dir=${TEST_DATA_DIR}
        -Djava.security.properties=${INSTALL_PROPERTY_FILE}
        ${TEST_JAVA_ARGS}
        com.amazon.corretto.crypto.provider.test.SecurityPropertyTester

    DEPENDS accp-jar tests-jar)

add_custom_target(check-install-via-properties-recursive
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${COVERAGE_ARGUMENTS}
        ${TEST_FIPS_PROPERTY}
        -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
        -Dtest.data.dir=${TEST_DATA_DIR}
        -Djava.security.properties=${INSTALL_PROPERTY_FILE}
        ${TEST_JAVA_ARGS}
        com.amazon.corretto.crypto.provider.test.SecurityPropertyRecursiveTester

    DEPENDS accp-jar tests-jar)

add_custom_target(check-install-via-properties-with-debug
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${COVERAGE_ARGUMENTS}
        ${TEST_FIPS_PROPERTY}
        -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        -Dcom.amazon.corretto.crypto.provider.inTestSuite=hunter2
        -Dtest.data.dir=${TEST_DATA_DIR}
        -Djava.security.properties=${INSTALL_PROPERTY_FILE}
        -Djava.security.debug=all
        ${TEST_JAVA_ARGS}
        com.amazon.corretto.crypto.provider.test.SecurityPropertyTester

    DEPENDS accp-jar tests-jar)

add_custom_target(check
    DEPENDS check-recursive-init check-install-via-properties check-install-via-properties-with-debug check-junit check-junit-SecurityManager check-external-lib)

add_custom_target(checkstyle
    WORKING_DIRECTORY ${ORIG_SRCROOT}
    COMMAND ${TEST_JAVA_EXECUTABLE}
        -cp ${CHECKSTYLE_CP}
        com.puppycrawl.tools.checkstyle.Main
        -c ${ORIG_SRCROOT}/checkstyle.xml
        ${ACCP_SRC}
)

if(ENABLE_NATIVE_TEST_HOOKS)
    add_custom_target(check-keyutils
        COMMAND ${CMAKE_COMMAND} -E copy ${OPENSSL_CRYPTO_LIBRARY} $<TARGET_FILE_DIR:test_keyutils>
        COMMAND $<TARGET_FILE:test_keyutils>
    )
    add_dependencies(check check-keyutils)
endif()

add_custom_target(coverage
    COMMAND ${TEST_JAVA_EXECUTABLE}
        -cp $<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        com.amazon.corretto.crypto.provider.coverage.ReportGenerator
        AmazonCorrettoCryptoProvider
        coverage/jacoco.exec
        $<TARGET_PROPERTY:code-only-jar,CLASSDIR>
        ${CMAKE_CURRENT_SOURCE_DIR}/src,${CMAKE_CURRENT_BINARY_DIR}/generated-java
        coverage/results

    DEPENDS check)

add_custom_target(check-integration-extra-checks
    COMMAND ${TEST_JAVA_EXECUTABLE}
        -Dcom.amazon.corretto.crypto.provider.extrachecks=ALL
        ${TEST_RUNNER_ARGUMENTS}
        --select-package=com.amazon.corretto.crypto.provider.test.integration

    DEPENDS accp-jar tests-jar)

set_target_properties(check-integration-extra-checks PROPERTIES EXCLUDE_FROM_ALL 1)

add_custom_target(check-integration
    COMMAND ${TEST_JAVA_EXECUTABLE}
        ${TEST_RUNNER_ARGUMENTS}
        --reports-dir=integration-tests
        --select-package=com.amazon.corretto.crypto.provider.test.integration

    DEPENDS accp-jar tests-jar)

set_target_properties(check-integration PROPERTIES EXCLUDE_FROM_ALL 1)

add_custom_target(run-benchmark
    COMMAND ${TEST_JAVA_EXECUTABLE} -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        com.amazon.corretto.crypto.provider.test.Benchmark

    DEPENDS accp-jar tests-jar)

set_target_properties(run-benchmark PROPERTIES EXCLUDE_FROM_ALL 1)

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

add_custom_target(run-dieharder-libcrypto-rng
    COMMAND ${TEST_JAVA_EXECUTABLE} -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        com.amazon.corretto.crypto.provider.test.SecureRandomGenerator 'LibCryptoRng' 8192 1 |
        ${DIEHARDER_EXECUTABLE} -a -g 200 -Y 1 -k 2 |
        tee dieharder-results-libcrypto-rng.txt

    DEPENDS accp-jar tests-jar)

add_custom_target(run-dieharder-libcrypto-rng-tail
    COMMAND ${TEST_JAVA_EXECUTABLE} -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        com.amazon.corretto.crypto.provider.test.SecureRandomGenerator 'LibCryptoRng' 31 1 |
        ${DIEHARDER_EXECUTABLE} -d 15 -g 200 -Y 1 -k 2 |
        tee dieharder-results-libcrypto-rng-tail.txt

    DEPENDS accp-jar tests-jar)

add_custom_target(run-dieharder-libcrypto-rng-threads
    COMMAND ${TEST_JAVA_EXECUTABLE} -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        com.amazon.corretto.crypto.provider.test.SecureRandomGenerator 'LibCryptoRng' 128 4 |
        ${DIEHARDER_EXECUTABLE} -a -g 200 -Y 1 -k 2 |
        tee dieharder-results-libcrypto-rng-threads.txt

    DEPENDS accp-jar tests-jar)

add_custom_target(run-dieharder-libcrypto-rng-threads-tail
    COMMAND ${TEST_JAVA_EXECUTABLE} -cp $<TARGET_PROPERTY:accp-jar,JAR_FILE>:$<TARGET_PROPERTY:tests-jar,JAR_FILE>:${TEST_CLASSPATH}
        ${EXTERNAL_LIB_PROPERTY}
        com.amazon.corretto.crypto.provider.test.SecureRandomGenerator 'LibCryptoRng' 31 4 |
        ${DIEHARDER_EXECUTABLE} -d 15 -g 200 -Y 1 -k 2 |
        tee dieharder-results-libcrypto-rng-threads-tail.txt

    DEPENDS accp-jar tests-jar)

  add_custom_target(check-dieharder
    COMMAND ! grep -l FAIL dieharder-results-libcrypto-rng.txt
    COMMAND grep PASSED dieharder-results-libcrypto-rng.txt
    COMMAND ! grep -l FAIL dieharder-results-libcrypto-rng-tail.txt
    COMMAND grep PASSED dieharder-results-libcrypto-rng-tail.txt

    DEPENDS run-dieharder-libcrypto-rng run-dieharder-libcrypto-rng-tail)

add_custom_target(check-dieharder-threads
    COMMAND ! grep -l FAIL dieharder-results-libcrypto-rng-threads.txt
    COMMAND grep PASSED dieharder-results-libcrypto-rng-threads.txt
    COMMAND ! grep -l FAIL dieharder-results-libcrypto-rng-threads-tail.txt
    COMMAND grep PASSED dieharder-results-libcrypto-rng-threads-tail.txt

    DEPENDS run-dieharder-libcrypto-rng-threads run-dieharder-libcrypto-rng-threads-tail)
endif() # End of Dieharder targets
# Do this at the end, after we finish all our feature tests, or it'll be missing flags
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/csrc/config.h.in ${JNI_HEADER_DIR}/config.h)
