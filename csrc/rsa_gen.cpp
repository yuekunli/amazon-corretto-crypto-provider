// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <cstring> // for memset
#include <stdio.h>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_RsaGen_generateEvpKey(
    JNIEnv* pEnv, jclass, jint bits, jboolean checkConsistency, jbyteArray pubExp)
{
    RSA_auto r = RSA_auto::from(RSA_new());

    try {
        raii_env env(pEnv);

        if (FIPS_mode() == 1) {
            // RSA_generate_key_fips performs extra checks so there is no need
            // to run post generation checks. This API generates keys with
            // public exponent F4; we ignore the public exponent here, but in
            // the Java layer, we check that the public exponent passed is F4.
            if (RSA_generate_key_fips(r, bits, NULL) != 1) {
                throw_openssl("Unable to generate key");
            }
        } else {
            // AWS-LC requires that the bitlength be a multiple of 128 and will round down.
            // We want to guarantee that we return a key of at least the requested strength and so must
            // round up. We only do this in the non-FIPS branch because in FIPS mode we want to do
            // exactly what the application requests.
            if (bits % 128 != 0) {
                bits += 128 - (bits % 128);
            }

            BigNumObj bne;
            jarr2bn(env, pubExp, bne);

            if (RSA_generate_key_ex(r, bits, bne, NULL) != 1) {
                throw_openssl("Unable to generate key");
            }

            if (checkConsistency && RSA_check_key(r) != 1) {
                throw_openssl("Key failed consistency check");
            }
        }

        EVP_PKEY_auto result = EVP_PKEY_auto::from(EVP_PKEY_new());
        CHECK_OPENSSL(result.isInitialized());
        CHECK_OPENSSL(EVP_PKEY_set1_RSA(result, r));

        return reinterpret_cast<jlong>(result.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}


JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_RsaGen_generateEvpKey_ossl3(
    JNIEnv* pEnv, jclass, jint bits, jboolean checkConsistency, jbyteArray pubExp)
{
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    try {
        raii_env env(pEnv);

        ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "RSA", NULL/*pror queue*/);
        
        EVP_PKEY_keygen_init(ctx);
        if (bits % 128 != 0) {
            bits += 128 - (bits % 128);
        }
        
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
        EVP_PKEY_generate(ctx, &pkey);

        if (checkConsistency)
        {
            int check_ret = 0;
            if ((check_ret = EVP_PKEY_check(ctx)) <= 0)
                throw_openssl("Key failed consistency check 1");
            if ((check_ret = EVP_PKEY_public_check(ctx)) <= 0)
                throw_openssl("Key failed consistency check 2");
            if ((check_ret = EVP_PKEY_private_check(ctx)) <= 0)
                throw_openssl("Key failed consistency check 3");
            if ((check_ret = EVP_PKEY_pairwise_check(ctx)) <= 0)
                throw_openssl("Key failed consistency check 4");
        }
        return reinterpret_cast<jlong>(pkey);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}