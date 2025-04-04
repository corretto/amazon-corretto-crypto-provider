// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_H
#define COMPILER_H

#include "config.h"
#include <stdint.h>

// DELETE_IMPLICIT is an alias for the '= delete' feature in C++11.
#define DELETE_IMPLICIT = delete
#define MOVE(x)         std::move(x)

#ifdef HAVE_ATTR_COLD
#define COLD __attribute__((cold))
#else
#define COLD
#endif

#ifdef HAVE_ATTR_NORETURN
#define NORETURN __attribute__((noreturn))
#else
#define NORETURN
#endif

#ifdef HAVE_ATTR_ALWAYS_INLINE
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif

#ifdef HAVE_ATTR_NOINLINE
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

#ifndef HAVE_NOEXCEPT
#define noexcept throw()
#endif

// See http://www.decompile.com/cpp/faq/file_and_line_error_string.htm
#define TO_STRING_0(x) #x
#define TO_STRING(x)   TO_STRING_0(x)

// Two levels of indirection as the preprocessor won't expand macros before
// concatenating. See:
// http://stackoverflow.com/questions/1489932/how-to-concatenate-twice-with-the-c-preprocessor-and-expand-a-macro-as-in-arg
#define CONCAT2_INTERNAL(a, b) a##b
#define CONCAT2(a, b)          CONCAT2_INTERNAL(a,b)

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x)          STRINGIFY_INTERNAL(x)

#define likely(x)   __builtin_expect(!!(x), true)
#define unlikely(x) __builtin_expect(!!(x), false)

#ifndef SIZE_MAX
#ifdef __SIZE_MAX__
#define SIZE_MAX __SIZE_MAX__
#else
#define SIZE_MAX (size_t(-1))
#endif
#endif

#endif
