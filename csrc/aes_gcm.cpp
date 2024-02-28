// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "auto_free.h"
#include "util.h"

#include <algorithm> // for std::min

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#define NATIVE_MODE_ENCRYPT 1
#define NATIVE_MODE_DECRYPT 0

#define EX_BADTAG   "javax/crypto/AEADBadTagException"
#define EX_SHORTBUF "javax/crypto/ShortBufferException"

// Number of bytes to process each time we lock the input/output byte arrays
#define CHUNK_SIZE (256 * 1024)

#define MAX_KEY_SIZE 32

#define KEY_LEN_AES128 16
#define KEY_LEN_AES192 24
#define KEY_LEN_AES256 32

using namespace AmazonCorrettoCryptoProvider;

static void initContext(raii_env& env, EVP_CIPHER_CTX* ctx, jint opMode, java_buffer key, java_buffer iv)
{
    ossl_auto<EVP_CIPHER> cipher;

    switch (key.len()) {
    case KEY_LEN_AES128:
        cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-GCM", NULL/*property queue*/);
        break;
    case KEY_LEN_AES192:
        cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-192-GCM", NULL/*property queue*/);
        break;
    case KEY_LEN_AES256:
        cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-265-GCM", NULL/*property queue*/);
        break;
    default:
        throw java_ex(EX_RUNTIME_CRYPTO, "Unsupported key length");
    }

    SecureBuffer<uint8_t, KEY_LEN_AES256> keybuf;
    key.get_bytes(env, keybuf.buf, 0, key.len());

    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    jni_borrow ivBorrow(env, iv, "iv");
    size_t ivlen = iv.len();
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen);

    EVP_CipherInit_ex2(ctx, cipher, keybuf, ivBorrow.data(), opMode, params);
}

static int updateLoop(raii_env& env, java_buffer out, java_buffer in, EVP_CIPHER_CTX* ctx)
{
    int total_output = 0;

    if (out.len() < in.len()) {
        throw java_ex(EX_ARRAYOOB, "Tried to process more data than would fit in the output buffer");
    }

    while (in.len() > 0) {
        jni_borrow outBorrow(env, out, "output");
        jni_borrow inBorrow(env, in, "input");
        size_t to_process = std::min((size_t)CHUNK_SIZE, in.len());

        int outl;
        int rv = EVP_CipherUpdate(ctx, outBorrow, &outl, inBorrow, to_process);

        if (unlikely(!rv)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "CipherUpdate failed");
        }

        if (unlikely((unsigned int)outl > outBorrow.len())) {
            env.fatal_error("Buffer overrun in cipher loop");
        }

        total_output += outl;
        out = out.subrange(outl);
        in = in.subrange(to_process);
    }

    return total_output;
}

static int cryptFinish(raii_env& env, int opMode, java_buffer resultBuf, unsigned int tagLen, EVP_CIPHER_CTX* ctx)
{
    if (opMode == NATIVE_MODE_ENCRYPT && unlikely(tagLen > resultBuf.len())) {
        throw java_ex(EX_SHORTBUF, "No space for GCM tag");
    }

    jni_borrow result(env, resultBuf, "result");

    int outl;
    int rv = EVP_CipherFinal_ex(ctx, result, &outl);

    if (unlikely(!rv)) {
        if (opMode == NATIVE_MODE_DECRYPT) {
            unsigned long errCode = drainOpensslErrors();
            if (likely(errCode == 0)) {
                throw java_ex(EX_BADTAG, "Tag mismatch!");
            } else {
                throw java_ex(EX_RUNTIME_CRYPTO, formatOpensslError(errCode, "CipherFinal failed"));
            }
        }
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "CipherFinal failed");
    }

    if (opMode == NATIVE_MODE_ENCRYPT && unlikely(tagLen + outl > resultBuf.len())) {
        throw java_ex(EX_SHORTBUF, "No space for GCM tag");
    }

    if (opMode == NATIVE_MODE_ENCRYPT) {

        OSSL_PARAM params[2] = {
            OSSL_PARAM_END, OSSL_PARAM_END
        };

        unsigned char* outtag = new unsigned char[tagLen];

        params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
            outtag, tagLen);

        EVP_CIPHER_CTX_get_params(ctx, params);

        memcpy(result.check_range(outl, tagLen), outtag, tagLen);

        outl += tagLen;

        delete outtag;
    }

    return outl;
}

static void updateAAD_loop(raii_env& env, EVP_CIPHER_CTX* ctx, java_buffer aadData)
{
    jni_borrow aad(env, aadData, "aad");

    int outl_ignored;
    if (!EVP_CipherUpdate(ctx, NULL, &outl_ignored, aad, aad.len())) {
        throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to update AAD state");
    }
}

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_oneShotEncrypt(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jlongArray ctxOut,
    jbyteArray inputArray,
    jint inoffset,
    jint inlen,
    jbyteArray resultArray,
    jint resultOffset,
    jint tagLen,
    jbyteArray keyArray,
    jbyteArray ivArray)
{
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        EVP_CIPHER_CTX* ctx;
        if (ctxPtr) {
            ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);

            jni_borrow ivBorrow(env, iv, "iv");

            if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_ENCRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
            }

        }
        else {
            ctx = EVP_CIPHER_CTX_new();
            java_buffer key = java_buffer::from_array(env, keyArray);
            initContext(env, ctx, NATIVE_MODE_ENCRYPT, key, iv);
        }

        int outoffset = updateLoop(env, result, input, ctx);
        if (outoffset < 0)
            return 0;

        result = result.subrange(outoffset);
        int finalOffset = cryptFinish(env, NATIVE_MODE_ENCRYPT, result, tagLen, ctx);

        if (!ctxPtr && ctxOut) {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx);
            env->SetLongArrayRegion(ctxOut, 0 /* start position */, 1 /* number of elements */, &tmpPtr);
        }

        return finalOffset + outoffset;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptInit__J_3B(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray ivArray)
{
    try {
        raii_env env(pEnv);

        if (!ctxPtr)
            throw java_ex(EX_NPE, "Null context");

        EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        jni_borrow ivBorrow(env, iv, "iv");

        if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_ENCRYPT))) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
        }
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptInit___3B_3B(
    JNIEnv* pEnv, jclass, jbyteArray keyArray, jbyteArray ivArray)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    try {
        raii_env env(pEnv);

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        initContext(env, ctx, NATIVE_MODE_ENCRYPT, key, iv);

        return reinterpret_cast<jlong>(ctx);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_releaseContext(JNIEnv*, jclass, jlong ctxPtr)
{
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);

    EVP_CIPHER_CTX_free(ctx);
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptUpdate(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jbyteArray inputArray,
    jint inoffset,
    jint inlen,
    jbyteArray resultArray,
    jint resultOffset)
{
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);

        EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);
        return updateLoop(env, result, input, ctx);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}


JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptUpdateAAD(
    JNIEnv* pEnv, jclass, jlong ctxPtr, jbyteArray input, jint offset, jint length)
{
    try {
        raii_env env(pEnv);
        if (!ctxPtr)
            throw java_ex(EX_NPE, "Null context");

        EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);
        java_buffer aadBuf = java_buffer::from_array(env, input, offset, length);

        updateAAD_loop(env, ctx, aadBuf);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_encryptDoFinal(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jboolean releaseContext,
    jbyteArray inputArray,
    jint inoffset,
    jint inlength,
    jbyteArray resultArray,
    jint resultOffset,
    jint tagLen)
{
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);

    int rv = -1;
    try {
        if (!ctx) {
            throw java_ex(EX_NPE, "Null context passed");
        }

        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlength);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);

        int outoffset = updateLoop(env, result, input, ctx);
        result = result.subrange(outoffset);
        int finalOffset = cryptFinish(env, NATIVE_MODE_ENCRYPT, result, tagLen, ctx);

        rv = outoffset + finalOffset;

        if (releaseContext)
            EVP_CIPHER_CTX_free(ctx);

    }
    catch (java_ex& ex) {
        EVP_CIPHER_CTX_free(ctx);

        ex.throw_to_java(pEnv);
        return -1;
    }

    return rv;
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesGcmSpi_oneShotDecrypt(JNIEnv* pEnv,
    jclass,
    jlong ctxPtr,
    jlongArray ctxOut,
    jbyteArray inputArray,
    jint inoffset,
    jint inlen,
    jbyteArray resultArray,
    jint resultOffset,
    jint tagLen,
    jbyteArray keyArray,
    jbyteArray ivArray,
    jbyteArray aadBuffer,
    jint aadSize)
{
    try {
        raii_env env(pEnv);

        java_buffer input = java_buffer::from_array(env, inputArray, inoffset, inlen);
        java_buffer result = java_buffer::from_array(env, resultArray, resultOffset);
        java_buffer iv = java_buffer::from_array(env, ivArray);

        EVP_CIPHER_CTX* ctx;
        if (ctxPtr) {
            ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr);

            jni_borrow ivBorrow(env, iv, "iv");
            if (unlikely(!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, ivBorrow.data(), NATIVE_MODE_DECRYPT))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set IV");
            }
        }
        else {
            ctx = EVP_CIPHER_CTX_new();
            java_buffer key = java_buffer::from_array(env, keyArray);
            initContext(env, ctx, NATIVE_MODE_DECRYPT, key, iv);
        }

        // Decrypt mode: Set the tag before we decrypt
        if (unlikely(tagLen > 16 || tagLen < 0)) {
            throw java_ex(EX_ILLEGAL_ARGUMENT, "Bad tag length");
        }

        if (unlikely(inlen < tagLen)) {
            throw java_ex(EX_BADTAG, "Input too short - need tag");
        }

        SecureBuffer<uint8_t, 16> tag;
        input.get_bytes(env, tag.buf, input.len() - tagLen, tagLen);

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, tag.buf)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to set GCM tag");
        }
        input = input.subrange(0, input.len() - tagLen);

        if (aadSize != 0) {
            updateAAD_loop(env, ctx, java_buffer::from_array(env, aadBuffer, 0, aadSize));
        }

        int outoffset = updateLoop(env, result, input, ctx);
        outoffset += cryptFinish(env, NATIVE_MODE_DECRYPT, result.subrange(outoffset), tagLen, ctx);

        if (!ctxPtr && ctxOut) {
            jlong tmpPtr = reinterpret_cast<jlong>(ctx);
            env->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
        }

        return outoffset;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

#ifdef __cplusplus
}
#endif