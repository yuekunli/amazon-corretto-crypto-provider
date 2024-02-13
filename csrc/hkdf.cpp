// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
//#include <openssl/crypto.h>
//#include <openssl/obj_mac.h>
//#include <openssl/params.h>

using namespace AmazonCorrettoCryptoProvider;

// The possible values of digestCode are defined in HkdfSecretKeyFactorySpi.java
/*
static EVP_MD const* digest_code_to_EVP_MD(int digestCode)
{
    switch (digestCode) {
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA1_CODE:
        return EVP_sha1();
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA256_CODE:
        return EVP_sha256();
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA384_CODE:
        return EVP_sha384();
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA512_CODE:
        return EVP_sha512();
    default:
        throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE.");
    }
}
*/

static void initialize_evp_kdf(EVP_KDF** kdf, EVP_KDF_CTX** ctx, int digestCode, OSSL_PARAM **p)
{
    *kdf = EVP_KDF_fetch(NULL/*lib ctx*/, "HKDF", NULL/*prop queue*/);

    *ctx = EVP_KDF_CTX_new(*kdf);

    switch (digestCode)
    {
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA1_CODE:
        char hash[7] = "SHA1";
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, hash, 0);
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA256_CODE:
        char hash[7] = "SHA256";
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, hash, 0);
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA384_CODE:
        char hash[7] = "SHA384";
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, hash, 0);
        break;
    case com_amazon_corretto_crypto_provider_HkdfSecretKeyFactorySpi_SHA512_CODE:
        char hash[7] = "SHA512";
        **p = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, hash, 0);
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
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;

    OSSL_PARAM params[6], * p = params;

    try {
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

        /*
        if (HKDF(output.get(), outputLen, digest, secret.get(), secretLen, salt.get(), saltLen, info.get(), infoLen)
            != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF failed.");
        }
        */
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);

    } catch (java_ex& ex) {

        if (ctx != NULL)
            EVP_KDF_CTX_free(ctx);

        if (kdf != NULL)
            EVP_KDF_free(kdf);

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
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;

    OSSL_PARAM params[5], * p = params;

    try {
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

        /*
        if (HKDF_extract(output.get(), &out_len, digest, secret.get(), secretLen, salt.get(), saltLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF_extract failed.");
        }
        assert(out_len == EVP_MD_size(digest) && out_len == outputLen);
        */

        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);

    } catch (java_ex& ex) {

        if (ctx != NULL)
            EVP_KDF_CTX_free(ctx);

        if (kdf != NULL)
            EVP_KDF_free(kdf);

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
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;

    OSSL_PARAM params[5], * p = params;

    try {
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

        /*
        if (HKDF_expand(output.get(), outputLen, digest, prk.get(), prkLen, info.get(), infoLen) != 1) {
            throw_openssl(EX_RUNTIME_CRYPTO, "HKDF_expand failed.");
        }
        */

        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);

    } catch (java_ex& ex) {

        if (ctx != NULL)
            EVP_KDF_CTX_free(ctx);

        if (kdf != NULL)
            EVP_KDF_free(kdf);

        ex.throw_to_java(env);
    }
}
