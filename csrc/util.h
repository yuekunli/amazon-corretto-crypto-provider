// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef UTIL_H
#define UTIL_H

#include "compiler.h"
#include "generated-headers.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <cstdlib>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>

namespace AmazonCorrettoCryptoProvider {

unsigned long drainOpensslErrors();

std::string formatOpensslError(unsigned long errorCode, const char* fallback);

inline std::string opensslErrorWithDefault(const char* fallback)
{
    return formatOpensslError(drainOpensslErrors(), fallback);
}

#define EX_CLASSNOTFOUND       "java/lang/NoClassDefFoundError"
#define EX_ERROR               "java/lang/Error"
#define EX_OOM                 "java/lang/OutOfMemoryError"
#define EX_NPE                 "java/lang/NullPointerException"
#define EX_ARRAYOOB            "java/lang/ArrayIndexOutOfBoundsException"
#define EX_INDEXOOB            "java/lang/IndexOutOfBoundsException"
#define EX_BADPADDING          "javax/crypto/BadPaddingException"
#define EX_SHORTBUFFER         "javax/crypto/ShortBufferException"
#define EX_RUNTIME_CRYPTO      "com/amazon/corretto/crypto/provider/RuntimeCryptoException"
#define EX_ILLEGAL_ARGUMENT    "java/lang/IllegalArgumentException"
#define EX_ILLEGAL_STATE       "java/lang/IllegalStateException"
#define EX_INVALID_KEY         "java/security/InvalidKeyException"
#define EX_INVALID_KEY_SPEC    "java/security/spec/InvalidKeySpecException"
#define EX_SIGNATURE_EXCEPTION "java/security/SignatureException"
#define CLASSNOTFOUND_TYPE     "java/lang/NoClassDefFoundError"


// Define this prior to use as some compilers don't like it the other way around.
static inline void secureZero(void* ptr, size_t size)
{
    if (ptr == nullptr || size == 0) {
        return;
    }
    memset(ptr, 0, size);
}

template <typename type, size_t size> 
class SecureBuffer {
public:
    type buf[size];

    SecureBuffer() { secureZero(buf, sizeof(buf)); }
    virtual ~SecureBuffer() { zeroize(); }
    operator type*() { return buf; }
    operator const type*() const { return buf; }

    // LiYK: I think the code in the original open source project is wrong, change "return &buf" to "return *buf"
    type& operator*() { return *buf; }
    const type& operator*() const { return *buf; }
    
    
    type& operator[](size_t idx) { return buf[idx]; }
    type& operator[](size_t idx) const { return buf[idx]; }
    virtual void zeroize() { secureZero(buf, sizeof(buf)); }
};

#if defined (_MSC_VER)
    #define hostToBigEndian64(x) htonll(x)
    #define bigEndianToHost64(x) ntohll(x)

#else // on non-microsoft compiler

    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

        #if defined(__x86_64__) 
            static inline uint64_t swapEndian(uint64_t val)
            {
                uint64_t result = val;
                __asm__("bswap %0" : "+r"(result));
                return result;
            }

            #define hostToBigEndian64(x) swapEndian(x)
            #define bigEndianToHost64(x) swapEndian(x)

        #else
  
            #define hostToBigEndian64(x) __builtin_bswap64(x)
            #define bigEndianToHost64(x) __builtin_bswap64(x)

        #endif

    #else // big endien:
        
        #define hostToBigEndian64(x) (x)
        #define bigEndianToHost64(x) (x)
    #endif

#endif // defined (_MSC_VER)

static inline void* fast_xor(void* dest, const void* src, int len)
{
    int idx = 0;
    uint8_t* dest8 = (uint8_t*)dest;
    uint8_t* src8 = (uint8_t*)src;
    for (; idx <= len - 8; idx += 8) {
        *((uint64_t*)(dest8 + idx)) ^= *((uint64_t*)(src8 + idx));
    }
    for (; idx < len; idx++) {
        dest8[idx] ^= src8[idx];
    }
    return dest;
}

static inline bool check_bounds(size_t length, size_t offset, size_t range_len)
{
    if (unlikely(range_len > length)) {
        return false;
    }

    if (unlikely(offset > length)) {
        return false;
    }

    size_t remaining = length - offset;
    return remaining >= range_len;
}

} // namespace AmazonCorrettoCryptoProvider

#endif
