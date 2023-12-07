// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_H
#define COMPILER_H

#include "config.h"
#include <stdint.h>

// __cplusplus is >= 201103L on C++11 or newer compilers. // LiYK: MSVC also defines _cplusplus, but we're certain in compiling with C++11 or higher

#define HAVE_CPP11

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

#define likely(x)   x
#define unlikely(x) x


#if defined (_MSC_VER)
#define FORCE_INLINE1 __inline
#define FORCE_INLINE2
#else
#define FORCE_INLINE1
#define FORCE_INLINE2 __attribute__((always_inline))
#endif


/**
 * LiYK: If there is an if clause like this:
 *     if (likely(...)) {
 * 
 *     }
 * just treat it as if "likely" isn't there at all, like this:
 *     if (...) {
 * 
 *     }
 * The same applies to "unlikely", just pretend it's there.
 * These two GCC built-in functions help arrange the location of assembly instructions
 * so that the CPU can fetch the more likely next instruction faster.
 *     
*/

#ifndef SIZE_MAX
#ifdef __SIZE_MAX__
#define SIZE_MAX __SIZE_MAX__
#else
#define SIZE_MAX (size_t(-1))
#endif
#endif

#endif
