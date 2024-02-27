// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "auto_free.h"
#include "util.h"

#include <openssl/evp.h>

#define AES_MAX_KEY_SIZE 32

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapPaddingSpi_wrapKey(JNIEnv* pEnv,
    jclass,
    jbyteArray keyArray,
    jbyteArray inputArray,
    jint inputLength,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        ossl_auto<EVP_CIPHER_CTX> ctx;
        ossl_auto<EVP_CIPHER> cipher;

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer input = java_buffer::from_array(env, inputArray, 0, inputLength);
        java_buffer output = java_buffer::from_array(env, outputArray, outputOffset);

        SecureBuffer<uint8_t, AES_MAX_KEY_SIZE> keybuf;
        if (key.len() > sizeof(keybuf.buf)) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key too large");
        }
        key.get_bytes(env, keybuf.buf, 0, key.len());

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        switch (key.len())
        {
        case 16:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-WRAP", NULL/*prop queue*/);
            break;
        case 24:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-192-WRAP", NULL/*prop queue*/);
            break;
        case 32:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-256-WRAP", NULL/*prop queue*/);
            break;
        default:
            throw_openssl(EX_RUNTIME_CRYPTO, "unrecognized AES key size");
        }
               
        EVP_EncryptInit_ex2(ctx, cipher, (uint8_t*)keybuf, NULL, NULL/*params*/);  // can IV be null?

        jni_borrow inbuf(env, input, "input");
        jni_borrow outbuf(env, output, "output");
        int outlen;
        int tmplen;

        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, input.len());

        EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
        outlen += tmplen;

        return outlen;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_AesKeyWrapPaddingSpi_unwrapKey(JNIEnv* pEnv,
    jclass,
    jbyteArray keyArray,
    jbyteArray inputArray,
    jint inputLength,
    jbyteArray outputArray,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        ossl_auto<EVP_CIPHER_CTX> ctx;
        ossl_auto<EVP_CIPHER> cipher;

        java_buffer key = java_buffer::from_array(env, keyArray);
        java_buffer input = java_buffer::from_array(env, inputArray, 0, inputLength);
        java_buffer output = java_buffer::from_array(env, outputArray, outputOffset);

        //AES_KEY aes_key;
        SecureBuffer<uint8_t, AES_MAX_KEY_SIZE> keybuf;
        if (key.len() > sizeof(keybuf.buf)) {
            throw_openssl(EX_RUNTIME_CRYPTO, "AES key too large");
        }
        key.get_bytes(env, keybuf.buf, 0, key.len());

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        switch (key.len())
        {
        case 16:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-WRAP", NULL/*prop queue*/);
            break;
        case 24:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-192-WRAP", NULL/*prop queue*/);
            break;
        case 32:
            cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-256-WRAP", NULL/*prop queue*/);
            break;
        default:
            throw_openssl(EX_RUNTIME_CRYPTO, "unrecognized AES key size");
        }

        EVP_DecryptInit_ex2(ctx, cipher, keybuf, NULL/*IV*/, NULL/*params*/);

        jni_borrow inbuf(env, input, "input");
        jni_borrow outbuf(env, output, "output");
        int outlen = 0, tmplen = 0;

        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, input.len());

        EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen);
        outlen += tmplen;

        return outlen;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
