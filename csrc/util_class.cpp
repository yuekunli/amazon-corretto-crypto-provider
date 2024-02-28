// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "generated-headers.h"

#include "env.h"
#include "keyutils.h"
#include "util.h"
#include "auto_free.h"

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

    ptrdiff_t diff = vB - vA;
    if (diff > 0 && diff >= lenA) {
        return no_overlap;
    }

    if (diff < 0 && -diff >= lenB) {
        return no_overlap;
    }

    if (diff < JINT_MIN || diff > JINT_MAX) {
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
        if (!mdName) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Null Digest name");
            return NULL;
        }
        jni_string name(env, mdName);
        ossl_auto<EVP_MD> md = EVP_MD_fetch(NULL/*lib ctx*/, name.native_str, NULL/*prop queue*/);
        return reinterpret_cast<jlong>(md.take());
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
