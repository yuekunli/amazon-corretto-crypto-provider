// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "auto_free.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace AmazonCorrettoCryptoProvider;

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_RsaGen_generateEvpKey(
    JNIEnv* pEnv, jclass, jint bits, jboolean checkConsistency, jbyteArray pubExp)
{
    try {
        ossl_auto<EVP_PKEY_CTX> ctx;
        ossl_auto<EVP_PKEY> pkey;
        ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "RSA", NULL/*pror queue*/);

        EVP_PKEY_keygen_init(ctx);
        /*
        if (bits % 128 != 0) {
            bits += 128 - (bits % 128);
        }
        */

        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
        EVP_PKEY_generate(ctx, &pkey);

        if (checkConsistency)
        {
            ossl_auto<EVP_PKEY_CTX> check_key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib context*/, pkey, NULL/*prop queue*/);
            int check_ret = 0;

            if ((check_ret = EVP_PKEY_public_check(check_key_ctx)) <= 0)
                throw_openssl("Key failed public component check");

            if ((check_ret = EVP_PKEY_private_check(check_key_ctx)) <= 0)
                throw_openssl("Key failed private component check");

            if ((check_ret = EVP_PKEY_pairwise_check(check_key_ctx)) <= 0)
                throw_openssl("Key failed pairwise check");
        }
        return reinterpret_cast<jlong>(pkey.take());
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

#ifdef __cplusplus
}
#endif