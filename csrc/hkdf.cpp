// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "auto_free.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

using namespace AmazonCorrettoCryptoProvider;

static char md5_name[] = "MD5";
static char sha1_name[] = "SHA1";
static char sha256_name[] = "SHA256";
static char sha384_name[] = "SHA384";
static char sha512_name[] = "SHA512";

static void initialize_evp_kdf(EVP_KDF** kdf, EVP_KDF_CTX** ctx, int digestCode, OSSL_PARAM **p)
{
    *kdf = EVP_KDF_fetch(NULL/*lib ctx*/, "HKDF", NULL/*prop queue*/);

    *ctx = EVP_KDF_CTX_new(*kdf);

    switch (digestCode)
    {
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA1_CODE:
        
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, sha1_name, sizeof(sha1_name));
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA256_CODE:
        
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, sha256_name, sizeof(sha256_name));
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA384_CODE:
        
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, sha384_name, sizeof(sha384_name));
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA512_CODE:
        
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, sha512_name, sizeof(sha512_name));
        break;
    default:
        throw java_ex(EX_ERROR, "Invalid hash algorithm in HKDF");
    }
    (*p)++;
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdf(JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jSalt,
    jint saltLen,
    jbyteArray jInfo,
    jint infoLen)
{
    try {

        ossl_auto<EVP_KDF> kdf;
        ossl_auto<EVP_KDF_CTX> ctx;

        OSSL_PARAM params[6], * p = params;
        
        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical secret(env, jSecret);
        JByteArrayCritical salt(env, jSalt);
        JByteArrayCritical info(env, jInfo);
        
        initialize_evp_kdf(&kdf, &ctx, digestCode, &p);

        int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret.get(), secretLen);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.get(), infoLen);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.get(), saltLen);

        *p = OSSL_PARAM_construct_end();

        EVP_KDF_derive(ctx, output.get(), outputLen, params);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdfExtract(
    JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jSecret,
    jint secretLen,
    jbyteArray jSalt,
    jint saltLen)
{
    try {
        ossl_auto<EVP_KDF> kdf;
        ossl_auto<EVP_KDF_CTX> ctx;

        OSSL_PARAM params[5], * p = params;

        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical secret(env, jSecret);
        JByteArrayCritical salt(env, jSalt);

        size_t out_len = 0;

        initialize_evp_kdf(&kdf, &ctx, digestCode, &p);

        int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret.get(), secretLen);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.get(), saltLen);

        *p = OSSL_PARAM_construct_end();

        out_len = EVP_KDF_CTX_get_kdf_size(ctx);
        assert((int)out_len == outputLen);

        EVP_KDF_derive(ctx, output.get(), outputLen, params);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_hkdfExpand(
    JNIEnv* env,
    jclass,
    jbyteArray jOutput,
    jint outputLen,
    jint digestCode,
    jbyteArray jPrk,
    jint prkLen,
    jbyteArray jInfo,
    jint infoLen)
{
    try {
        ossl_auto<EVP_KDF> kdf;
        ossl_auto<EVP_KDF_CTX> ctx;
        
        OSSL_PARAM params[5], * p = params;

        JByteArrayCritical output(env, jOutput);
        JByteArrayCritical prk(env, jPrk);
        JByteArrayCritical info(env, jInfo);

        initialize_evp_kdf(&kdf, &ctx, digestCode, &p);

        int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prk.get(), prkLen);

        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, info.get(), infoLen);

        *p = OSSL_PARAM_construct_end();

        EVP_KDF_derive(ctx, output.get(), outputLen, params);

    } catch (java_ex& ex) {
        ex.throw_to_java(env);
    }
}
