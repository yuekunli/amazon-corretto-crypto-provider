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

/*
 * Class:     com_amazon_corretto_crypto_provider_EcGen
 * Method:    buildEcParams
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_buildEcParams(JNIEnv* pEnv, jclass, jint nid)
{
    //EVP_PKEY_CTX_auto paramCtx;

    EVP_PKEY_CTX* paramCtx = NULL;
    EVP_PKEY* param = NULL;
    jlong retval;

    try {
        //paramCtx.set(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));

        paramCtx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "EC", NULL/*prop queue*/);

        /*
        if (!paramCtx.isInitialized()) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to create param context");
        }
        */


        if (!EVP_PKEY_paramgen_init(paramCtx)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize param context");
        }

        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, nid)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to set curve");
        }

        
        if (!EVP_PKEY_paramgen(paramCtx, &param)) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to generate parameters");
        }
        if (paramCtx != NULL)
            EVP_PKEY_CTX_free(paramCtx);
        retval = (jlong)param;
    } catch (java_ex& ex) {
        if (param != NULL)
            EVP_PKEY_free(param);
        if (paramCtx != NULL)
            EVP_PKEY_CTX_free(paramCtx);
        ex.throw_to_java(pEnv);
        retval = 0;
    }

    return retval;
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

void generateEcKey(raii_env* env, EVP_PKEY** key, EVP_PKEY* param, jboolean checkConsistency)
{
    //EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new(param, NULL));

    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, param, NULL/*prop queue*/);

    //CHECK_OPENSSL(ctx.isInitialized());
    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx) > 0);
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key/*key.getAddressOfPtr() */ ));
    if (checkConsistency) {
        /*
        EC_KEY* ecKey = NULL;
        CHECK_OPENSSL(ecKey = EVP_PKEY_get1_EC_KEY(key));
        int check_result = EC_KEY_check_key(ecKey);
        EC_KEY_free(ecKey);
        CHECK_OPENSSL(check_result);
        */
        CHECK_OPENSSL(EVP_PKEY_check(ctx) == 1);
    }
    EVP_PKEY_CTX_free(ctx);
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKey(
    JNIEnv* pEnv, jclass, jlong param, jboolean checkConsistency)
{
    try {
        raii_env env(pEnv);

        // Actually set up the key
        EVP_PKEY* key = NULL;
        generateEcKey(&env, &key, reinterpret_cast<EVP_PKEY*>(param), checkConsistency);
        return reinterpret_cast<jlong>(key);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcGen_generateEvpEcKeyFromSpec(
    JNIEnv* pEnv, jclass, jbyteArray paramsDer, jboolean checkConsistency)
{
    std::vector<uint8_t, SecureAlloc<uint8_t> > derBuf;
    //EC_KEY_auto ecParams;
    //EVP_PKEY_auto params_as_pkey = EVP_PKEY_auto::from(EVP_PKEY_new());
    EVP_PKEY* params_as_pkey = NULL;
    EVP_PKEY* key = NULL;
    OSSL_DECODER_CTX* decoder_ctx = NULL;
    try {
        raii_env env(pEnv);

        // First, parse the params
        derBuf = java_buffer::from_array(env, paramsDer).to_vector(env);
        const unsigned char* tmp = (const unsigned char*)&derBuf[0]; // necessary due to modification

        /*
        if (!likely(ecParams.set(d2i_ECParameters(NULL, &tmp, derBuf.size())))) {
            throw_openssl("Unable to parse parameters");
        }

        CHECK_OPENSSL(EVP_PKEY_assign_EC_KEY(params_as_pkey, ecParams.take())); // Takes ownership of ecParams
        */

        int selection = EVP_PKEY_KEY_PARAMETERS;  // evp.h

        const char* structure = "type-specific";

        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&params_as_pkey, "DER", structure, "EC", selection, NULL/*lib ctx*/, NULL/*prop queue*/);
        size_t derBufLen = derBuf.size();
        OSSL_DECODER_from_data(decoder_ctx, &tmp, &derBufLen);
        OSSL_DECODER_CTX_free(decoder_ctx);

        generateEcKey(&env, &key, params_as_pkey, checkConsistency);

        EVP_PKEY_free(params_as_pkey);

        return reinterpret_cast<jlong>(key);
    } catch (java_ex& ex) {
        if (decoder_ctx != NULL)
            OSSL_DECODER_CTX_free(decoder_ctx);
        if (params_as_pkey != NULL)
            EVP_PKEY_free(params_as_pkey);
        ex.throw_to_java(pEnv);
        return 0;
    }
}
