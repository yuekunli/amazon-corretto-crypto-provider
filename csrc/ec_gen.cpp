// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <memory>

using namespace AmazonCorrettoCryptoProvider;

static void generateEcKey(raii_env* env, EVP_PKEY** key, EVP_PKEY* param, jboolean checkConsistency)
{
    ossl_auto<EVP_PKEY_CTX> ctx;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, param, NULL/*prop queue*/);

    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx) > 0);
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key));
    if (checkConsistency) {
        ossl_auto<EVP_PKEY_CTX> check_key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib context*/, *key, NULL/*prop queue*/);
        CHECK_OPENSSL(EVP_PKEY_check(check_key_ctx) == 1);
    }
}

#ifdef __cplusplus
extern "C" {
#endif

/*
* Class:     com_amazon_corretto_crypto_provider_EcGen
* Method:    buildEcParams
* Signature: (I)J
*/
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_buildEcParams(JNIEnv* pEnv, jclass, jint nid)
{
    try {
        ossl_auto<EVP_PKEY_CTX> paramCtx;
        ossl_auto<EVP_PKEY> param;

        paramCtx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "EC", NULL/*prop queue*/);

        if (!EVP_PKEY_paramgen_init(paramCtx)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize param context");
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, nid)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to set curve");
        }

        if (!EVP_PKEY_paramgen(paramCtx, &param)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to generate parameters");
        }
        return reinterpret_cast<jlong>(param.take());
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
* Class:     com_amazon_corretto_crypto_provider_EcGen
* Method:    freeEcParams
* Signature: (J)V
*/
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_freeEcParams(JNIEnv* env, jclass, jlong param)
{
    EVP_PKEY_free((EVP_PKEY*)param);
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKey(
    JNIEnv* pEnv, jclass, jlong param, jboolean checkConsistency)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = NULL;
        generateEcKey(&env, &key, reinterpret_cast<EVP_PKEY*>(param), checkConsistency);
        return reinterpret_cast<jlong>(key);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKeyFromSpec(
    JNIEnv* pEnv, jclass, jbyteArray paramsDer, jboolean checkConsistency)
{
    try {
        raii_env env(pEnv);

        std::vector<uint8_t, SecureAlloc<uint8_t> > derBuf;
        ossl_auto<EVP_PKEY> params_as_pkey;
        ossl_auto<EVP_PKEY> key;
        ossl_auto<OSSL_DECODER_CTX> decoder_ctx;

        derBuf = java_buffer::from_array(env, paramsDer).to_vector(env);
        const unsigned char* tmp = (const unsigned char*)&derBuf[0]; // necessary due to modification

        int selection = EVP_PKEY_KEY_PARAMETERS;  // evp.h
        const char* structure = "type-specific";
        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&params_as_pkey, "DER", structure, "EC", selection, NULL/*lib ctx*/, NULL/*prop queue*/);
        size_t derBufLen = derBuf.size();
        OSSL_DECODER_from_data(decoder_ctx, &tmp, &derBufLen);
        generateEcKey(&env, &key, params_as_pkey, checkConsistency);
        return reinterpret_cast<jlong>(key.take());
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

#ifdef __cplusplus
}
#endif
