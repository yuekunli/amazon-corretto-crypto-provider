// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.                                                                                                                                                                       2 // SPDX-License-Identifier: Apache-2.0
#ifndef CONFIG_H
#define CONFIG_H 1

/* #undef HAVE_ATTR_COLD */
/* #undef HAVE_ATTR_NORETURN */
/* #undef HAVE_ATTR_ALWAYS_INLINE */
/* #undef HAVE_ATTR_NOINLINE */
/* #undef HAVE_GETENTROPY */
/* #undef HAVE_GETENTROPY_IN_SYSRANDOM */
/* #undef BACKTRACE_ON_EXCEPTION */
#define HAVE_IS_TRIVIALLY_COPYABLE
/* #undef HAVE_IS_TRIVIALLY_DESTRUCTABLE */
/* #undef HAVE_NULLPTR */
#define HAVE_NOEXCEPT
/* #undef ENABLE_NATIVE_TEST_HOOKS */

#ifdef HAVE_GETENTROPY_IN_SYSRANDOM
#define HAVE_GETENTROPY
#endif

#endif