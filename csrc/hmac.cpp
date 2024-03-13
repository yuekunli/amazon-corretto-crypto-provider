// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "util.h"
#include "auto_free.h"

#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define NEED_COMPLETE_REINITIALIZE 0
#define RESET_INPUT_KEEP_KEY_AND_MD 1

using namespace AmazonCorrettoCryptoProvider;

namespace {

    char md5_name[] = "MD5";
    char sha1_name[] = "SHA1";
    char sha256_name[] = "SHA256";
    char sha384_name[] = "SHA384";
    char sha512_name[] = "SHA512";

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
        ossl_auto<EVP_MAC> mac;

        mac = EVP_MAC_fetch(NULL/*lib ctx*/, "HMAC", NULL/*prop queue*/);
        *ctx = EVP_MAC_CTX_new(mac);

        switch (md_algo)
        {
        case 0:
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, md5_name, sizeof(md5_name));
            // hopefully digest_name is copied into parameter, so when execution is out of this case block, i.e. digest name is destroied, parameter is still valid
            break;
        case 1:
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha1_name, sizeof(sha1_name));
            break;
        case 2:
            * p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha256_name, sizeof(sha256_name));
            break;
        case 3:
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha384_name, sizeof(sha384_name));
            break;
        case 4:
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha512_name, sizeof(sha512_name));
            break;
        }
        *p = OSSL_PARAM_construct_end();

        EVP_MAC_init(*ctx, key.data(), key.len(), params);
    }
}

void add_input(raii_env& env, EVP_MAC_CTX* ctx, jni_borrow& input)
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

    result.put_bytes(env, scratch, 0, macSize);
}
}

#ifdef __cplusplus
extern "C" {
#endif

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
    try {
        raii_env env(pEnv);

        ossl_auto<EVP_MAC_CTX> ctx;

        bool copyCtxPtrToJava = false;

        if (instruction == NEED_COMPLETE_REINITIALIZE)
        {
            copyCtxPtrToJava = true;
            maybe_init_ctx(env, &ctx, keyArr, digest_code, instruction);
        }
        else if (instruction == RESET_INPUT_KEEP_KEY_AND_MD)
        {
            ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
            maybe_init_ctx(env, &ctx, keyArr, digest_code, instruction);
        }
        else  // continuous update
        {
            ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
        }
        
        {
            java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
            jni_borrow input(env, inputBuf, "input");
            add_input(env, ctx, input);
        } // braces defining a scope, jni_borrow is destructed in a timely manner.

        if (copyCtxPtrToJava)
        {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }
        ctx.releaseOwnership();

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
    try {
        raii_env env(pEnv);

        ossl_auto<EVP_MAC_CTX> ctx;
        bool copyCtxPtrToJava = false;

        java_buffer inputBuf = java_buffer::from_array(env, inputArr, offset, len);
        java_buffer resultBuf = java_buffer::from_array(env, resultArr);

        if (instruction == NEED_COMPLETE_REINITIALIZE)
        {
            copyCtxPtrToJava = true;
            maybe_init_ctx(env, &ctx, keyArr, digestCode, instruction);
        }
        else if (instruction == RESET_INPUT_KEEP_KEY_AND_MD)
        {
            ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
            maybe_init_ctx(env, &ctx, keyArr, digestCode, instruction);
        }
        else // continuous update
        {
            ctx = reinterpret_cast<EVP_MAC_CTX*>(ctxPtr);
        }

        { // this pair of braces set up a scope so that jni_borrow is destructed when out of scope, so that env is not locked anymore, so that I can call other JNI functions
            jni_borrow input(env, inputBuf, "input");
            add_input(env, ctx, input);
            calculate_mac(env, ctx, resultBuf);
        }

        if (copyCtxPtrToJava)
        {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }
        ctx.releaseOwnership();
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

#ifdef __cplusplus
}
#endif
