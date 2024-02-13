// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "util.h"
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define NEED_COMPLETE_REINITIALIZE 0
#define RESET_INPUT_KEEP_KEY_AND_MD 1

using namespace AmazonCorrettoCryptoProvider;

// Some of the logic around how to manage arrays is non-standard because HMAC is extremely performance sensitive.
// For the smaller data-sizes we're using, avoiding GetPrimitiveArrayCritical is worth it.

namespace {

    // We pass in keyArr as a jbyteArray to avoid even the minimimal JNI costs
    // of wrapping it in a java_buffer when we don't need it.
void maybe_init_ctx(raii_env& env, EVP_MAC_CTX** ctx, jbyteArray& keyArr, jint md_algo, jint instruction)
{
    if (instruction == RESET_INPUT_KEEP_KEY_AND_MD)
    {
        EVP_MAC_init(*ctx, NULL, 0, NULL);
        return;
    }

    if (instruction == NEED_COMPLETE_REINITIALIZE)
    {    
        java_buffer keyBuf = java_buffer::from_array(env, keyArr);
        jni_borrow key(env, keyBuf, "key");
        
        OSSL_PARAM params[2], * p = params;
        EVP_MAC* mac = NULL;

        mac = EVP_MAC_fetch(NULL/*lib ctx*/, "HMAC", NULL/*prop queue*/);

        switch (md_algo)
        {
        case 0:
            char digest_name[] = "MD5";
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
            break;
        case 1:
            char digest_name[] = "SHA1";
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
            break;
        case 2:
            char digest_name[] = "SHA256";
            * p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
            break;
        case 3:
            char digest_name[] = "SHA384";
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
            break;
        case 4:
            char digest_name[] = "SHA512";
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
            break;
        }
        *p = OSSL_PARAM_construct_end();

        EVP_MAC_init(*ctx, key.data(), key.len(), params);
    }
}

void update_ctx(raii_env& env, EVP_MAC_CTX* ctx, jni_borrow& input)
{
    if (unlikely(EVP_MAC_update(ctx, input.data(), input.len()) != 1)) {
        throw_openssl("Unable to update HMAC_CTX");
    }
}

void calculate_mac(raii_env& env, EVP_MAC_CTX* ctx, java_buffer& result)
{
    uint8_t scratch[EVP_MAX_MD_SIZE];
    size_t macSize = EVP_MAX_MD_SIZE;

    EVP_MAC_final(ctx, NULL, &macSize, 0);

    if (unlikely(EVP_MAC_final(ctx, scratch, &macSize, macSize) != 1)) {
        throw_openssl("Unable to update HMAC_CTX");
    }
    // When we don't need to read the data in an array but use it strictly for output
    // it can be faster to use put_bytes rather than convert it into a jni_borrow.
    result.put_bytes(env, scratch, 0, macSize);
}
}

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    getContextSize
 * Signature: ()I
 */
/*
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_getContextSize(JNIEnv*, jclass)
{
    return sizeof(HMAC_CTX);
}
*/


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    updateCtxArray
 * Signature: ([B[BJ[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_updateCtxArray(
    JNIEnv* pEnv, 
    jclass, 
    jlong ctxPtr, 
    jlongArray ctxOut, 
    jint instruction,
    jint digest_code,
    jbyteArray keyArr,
    jbyteArray inputArr, 
    jint offset, 
    jint len)
{
    EVP_MAC_CTX* ctx = NULL;
    try {
        raii_env env(pEnv);
        bool copyCtxPtrToJava = false;

        if (instruction == NEED_COMPLETE_REINITIALIZE || instruction == RESET_INPUT_KEEP_KEY_AND_MD)
        {
            copyCtxPtrToJava = (instruction == NEED_COMPLETE_REINITIALIZE);
            maybe_init_ctx(env, &ctx, keyArr, digest_code, instruction);
        }
        else
        {
            EVP_MAC_CTX* ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
        }

        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
        jni_borrow input(env, inputBuf, "input");
        update_ctx(env, ctx, input);

        if (copyCtxPtrToJava)
        {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx);
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }


    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    doFinal
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_doFinal(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray resultArr)
{
    try {
        raii_env env(pEnv);
        EVP_MAC_CTX* ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);

        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        calculate_mac(env, ctx, resultBuf);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    fastHmac
 * Signature: ([B[BJ[BII[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_fastHmac(
    JNIEnv* pEnv,
    jclass clazz,
    jlong ctxPtr,
    jlongArray ctxOut,
    jint instruction,
    jint digestCode,
    jbyteArray keyArr,
    jbyteArray inputArr,
    jint offset,
    jint len,
    jbyteArray resultArr)
{
    // We do not depend on the other methods because it results in more use to JNI than we want and lower performance

    EVP_MAC_CTX* ctx = NULL;

    try {
        raii_env env(pEnv);

        bool copyCtxPtrToJava = false;

        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        if (instruction == NEED_COMPLETE_REINITIALIZE || instruction == RESET_INPUT_KEEP_KEY_AND_MD)
        {
            copyCtxPtrToJava = (instruction == NEED_COMPLETE_REINITIALIZE);
            maybe_init_ctx(env, &ctx, keyArr, digestCode, instruction);
        }
        else
        {
            ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
        }
        {
            jni_borrow input(env, inputBuf, "input");
            update_ctx(env, ctx, input);
        }
        {
            calculate_mac(env, ctx, resultBuf);
        }

        if (copyCtxPtrToJava)
        {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx);
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

#ifdef __cplusplus
}
#endif
