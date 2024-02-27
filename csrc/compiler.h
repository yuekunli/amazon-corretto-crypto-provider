// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_H
#define COMPILER_H

#include <stdint.h>

#define TO_STRING_0(x) #x
#define TO_STRING(x)   TO_STRING_0(x)

#define CONCAT2_INTERNAL(a, b) a##b
#define CONCAT2(a, b)          CONCAT2_INTERNAL(a,b)

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x)          STRINGIFY_INTERNAL(x)


#if __cplusplus >= 201103L || (defined(_MSVC_LANG) && _MSVC_LANG > 201103L)
	#define HAVE_CPP11
	#define DELETE_IMPLICIT = delete
	#define MOVE(x)         std::move(x)
	#define HAVE_IS_TRIVIALLY_COPYABLE

#else
	#define DELETE_IMPLICIT
	#define nullptr NULL
	#define MOVE(x) (x)
	#define noexcept throw()
#endif


#ifdef __GNUC__

	#define COLD __attribute__((cold))
	
	#define NORETURN1
	#define NORETURN2 __attribute__((noreturn))

	#define NOINLINE1
	#define NOINLINE2 __attribute__(noinline)

	#define FORCE_INLINE1
	#define FORCE_INLINE2 __attribute__((always_inline))

	#define likely(x)   __builtin_expect(!!(x), true)
	#define unlikely(x) __builtin_expect(!!(x), false)

#elif defined(_MSC_VER)

	#define COLD

	#define NORETURN1 __declspec(noreturn)
	#define NORETURN2

	#define NOINLINE1 __declspec(noinline)
	#define NOINLINE2 

	#define FORCE_INLINE1 __forceinline
	#define FORCE_INLINE2

	#define likely(x)   x
	#define unlikely(x) x

#else

	#define COLD
	#define NORETURN1
	#define NORETURN2
	#define NOINLINE1
	#define NOINLINE2
	#define FORCE_INLINE1
	#define FORCE_INLINE2
	#define likely(x)   x
	#define unlikely(x) x

#endif


#ifndef SIZE_MAX  // stdint.h  this is available since C++11
	#ifdef __SIZE_MAX__
		#define SIZE_MAX __SIZE_MAX__
	#else
		#define SIZE_MAX (size_t(-1))
	#endif
#endif

#ifndef UINT64_MAX
#ifdef __UINT64_MAX__
#define UINT64_MAX __UINT64_MAX__
#else
#define UINT64_MAX (~((uint64_t)0))
#endif
#endif

#endif
