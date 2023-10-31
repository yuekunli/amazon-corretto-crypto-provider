// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "generated-headers.h"

#include "env.h"
#include "keyutils.h"
#include "util.h"
// JNI methods needed by the Java Utils class rather than generic utilities needed by our code.

using namespace AmazonCorrettoCryptoProvider;

extern "C" {

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getNativeBufferOffset
 * Signature: (Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)J
 */

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getNativeBufferOffset(
    JNIEnv* env, jclass, jobject bufA, jobject bufB)
{
    const jlong JINT_MAX = (1L << 31) - 1L;
    const jlong JINT_MIN = -(1L << 31);

    // LiYK: Note that every integer literal is by default signed.
    // "1L" makes sure this is a long, whether it's 32-bit or 64-bit depends on platform,
    // but even if it's 32-bit, it's going to be promoted to the same length as jlong.
    // note that jlong is a 64 bit signed integer. (1L << 31) only moves to the 32nd bit, 
    // and gives me 2,147,483,648, it's still well within the range of 64 bit signed number, 
    // the negative sign means I want the compiler to store the proper representation
    // of -2,147,483,648, the compiler will do the 2's complement conversion to get the
    // correct representation of -2,147,483,648.
    // In fact, the compiler will fill the high 32 bits with 1's. That is how -2,147,483,648 is
    // represented in 2's complement in 64 bits number
    
    const jlong no_overlap = JINT_MAX + 1L;

    void* pA = env->GetDirectBufferAddress(bufA);
    void* pB = env->GetDirectBufferAddress(bufB);

    if (!pA || !pB) {
        return no_overlap;
    }

    jlong lenA = env->GetDirectBufferCapacity(bufA);
    jlong lenB = env->GetDirectBufferCapacity(bufB);

    uintptr_t vA = (uintptr_t)pA;
    uintptr_t vB = (uintptr_t)pB;

    ptrdiff_t diff = vB - vA;  // LiYK: ptrdiff is signed long long which is signed 64-bit
    if (diff > 0 && diff >= lenA) {
        // B is located after A's end, so there's no real overlap
        return no_overlap;
    }

    if (diff < 0 && -diff >= lenB) {
        // A is located after B's end, so no real overlap
        return no_overlap;
    }

    // diff should be within jint's bounds now, as direct buffers can't be larger
    // than can be represented by an int
    if (diff < JINT_MIN || diff > JINT_MAX) {   // LiYK: diff is signed 64 bits, JINT_MAX and JINT_MIN are also 64 bits but are used to represent 32 bits signed.
        throw_java_ex(EX_RUNTIME_CRYPTO, "Overlap outside range of jint");
    }

    return diff;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getEvpMdFromName
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getEvpMdFromName(
    JNIEnv* pEnv, jclass, jstring mdName)
{
    try {
        raii_env env(pEnv);
        return reinterpret_cast<jlong>(digestFromJstring(env, mdName));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_Utils
 * Method:    getDigestLength
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_Utils_getDigestLength(JNIEnv*, jclass, jlong evpMd)
{
    return EVP_MD_size(reinterpret_cast<const EVP_MD*>(evpMd));
}
}
