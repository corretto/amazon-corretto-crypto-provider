# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.8)
project(TryCompile)

set(LINK_FLAGS "" CACHE STRING "")
set(LINK_LIBS "" CACHE STRING "")
set(OPENSSL_INCLUDE_DIR "" CACHE STRING "")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_SHARED_LINKER_FLAGS "-shared ${LINK_FLAGS}")

include_directories( ${OPENSSL_INCLUDE_DIR} )

# For generic linker flag tests, we just use an empty C++ file to try to build
# an empty C++ shared library.
add_library(empty SHARED empty.cxx)

add_executable(coverage coverage_main.cxx)
target_compile_options(coverage PRIVATE -fprofile-arcs -ftest-coverage)
set_target_properties(coverage PROPERTIES LINK_FLAGS "-fprofile-arcs -ftest-coverage")
