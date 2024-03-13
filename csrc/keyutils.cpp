// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "keyutils.h"
#include "bn.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <openssl/encoder.h>


namespace AmazonCorrettoCryptoProvider {

EVP_PKEY* der2EvpPrivateKey(
    const unsigned char* der,
    const int derLen,
    bool shouldCheckPrivate,
    const char* javaExceptionClass)
{
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer
    ossl_auto<EVP_PKEY_CTX> ctx;
    ossl_auto<PKCS8_PRIV_KEY_INFO> pkcs8Key = d2i_PKCS8_PRIV_KEY_INFO(NULL, &der_mutable_ptr, derLen);  // still available in 3.0
    if (der + derLen != der_mutable_ptr) {
        //if (pkcs8Key.isInitialized()) {
        //    PKCS8_PRIV_KEY_INFO_free(pkcs8Key);
        //}
        throw_openssl(javaExceptionClass, "Extra key information");
    }
    if (!pkcs8Key.isInitialized()) {
        throw_openssl(javaExceptionClass, "Unable to parse DER key into PKCS8_PRIV_KEY_INFO");
    }
    ossl_auto<EVP_PKEY> pkey = EVP_PKCS82PKEY(pkcs8Key);  // still available in 3.0
    if (!pkey.isInitialized()) {
        throw_openssl(javaExceptionClass, "Unable to convert PKCS8_PRIV_KEY_INFO to EVP_PKEY");
    }
    
    bool need_rebuild = false;

    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        BigNumObj n, e, d, p, q, dmp1, dmq1, iqmp;

        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);



        if (!e || BN_is_zero(e))
            need_rebuild = true;

        if (p && BN_is_zero(p)) {
            need_rebuild = true;
        }
        else if (q && BN_is_zero(q)) {
            need_rebuild = true;
        }
        else if (dmp1 && BN_is_zero(dmp1)) {
            need_rebuild = true;
        }
        else if (dmq1 && BN_is_zero(dmq1)) {
            need_rebuild = true;
        }
        else if (iqmp && BN_is_zero(iqmp)) {
            need_rebuild = true;
        }

#ifdef REBUILD_RSA_KEY_WHEN_PUBLIC_EXP_MISSING
        if (need_rebuild)
        {
            ossl_auto<EVP_PKEY_CTX> ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "RSA", NULL/*prop queue*/);
            ossl_auto<EVP_PKEY> rebuild_pkey = NULL;

            ossl_auto<OSSL_PARAM_BLD> paramBuild = NULL;
            ossl_auto<OSSL_PARAM> params = NULL;

            paramBuild = OSSL_PARAM_BLD_new();

            //BIGNUM* pub_exponent = NULL;
            BigNumObj pub_exponent;
            if (!e || BN_is_zero(e)) {  // public exponent must be present
                static unsigned char pub_exponent_array[] = {
                    0x01, 0x00, 0x01
                };
                *(&pub_exponent) = BN_bin2bn(pub_exponent_array, 3, NULL);
                OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, pub_exponent);
                //BN_free(pub_exponent); pub_exponent is not copied to params until OSSL_PARAM_BLD_to_param is called.
            }
            else {
                
                OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, e);
            }

            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_N, n);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_D, d);

            params = OSSL_PARAM_BLD_to_param(paramBuild);

            EVP_PKEY_fromdata_init(ctx);
            EVP_PKEY_fromdata(ctx, &rebuild_pkey, EVP_PKEY_KEYPAIR, params);
            
#ifdef LYK_DEBUG
            {
                ossl_auto<unsigned char>der;
                ossl_auto<OSSL_ENCODER_CTX> encoder_ctx;
                size_t derLen = 0;
                
                int selection = EVP_PKEY_KEYPAIR;
                int ret;
                encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "PrivateKeyInfo", NULL/*prop queue*/);
                ret = OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);

                if (ret == 0)
                {
                    encoder_ctx.clear();
                    selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
                    encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "PrivateKeyInfo", NULL/*prop queue*/);
                    ret = OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);
                }

                std::cout << ret << "\n";

            }

            {
                ossl_auto<unsigned char>der;
                ossl_auto<OSSL_ENCODER_CTX> encoder_ctx;
                size_t derLen = 0;

                int selection = EVP_PKEY_KEYPAIR;
                int ret;
                encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(rebuild_pkey, selection, "DER", "PrivateKeyInfo", NULL/*prop queue*/);
                ret = OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);

                if (ret == 0)
                {
                    encoder_ctx.clear();
                    selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
                    encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(rebuild_pkey, selection, "DER", "PrivateKeyInfo", NULL/*prop queue*/);
                    ret = OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);
                }

                std::cout << ret << "\n";

            }
#endif
            pkey.clear();
            pkey.set(rebuild_pkey.take());
        }
#endif
     }

    if (shouldCheckPrivate)
    {
        if (!ctx.isInitialized())
        {
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib context*/, pkey, NULL/*prop queue*/);
        }

        //if (!EVP_PKEY_private_check(ctx))
        //    throw_openssl(javaExceptionClass, "failed key private check");
        
        if (!EVP_PKEY_param_check(ctx))
            throw_openssl(javaExceptionClass, "failed key parameters check");
        
        if (!need_rebuild && !EVP_PKEY_public_check(ctx))
            throw_openssl(javaExceptionClass, "failed key public check");
        
        if (!need_rebuild && !EVP_PKEY_pairwise_check(ctx)) 
            // only do pairwise check if key is not rebuilt, 
            //because rebuilt key doesn't have CRT parameters, and pairwise check tests exactly those parameters
            throw_openssl(javaExceptionClass, "failed key pairwise check");
    }

    return pkey.take();
}

EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass)
{
    const unsigned char* der_mutable_ptr = der; // openssl modifies the input pointer

    ossl_auto<EVP_PKEY> result = d2i_PUBKEY(NULL, &der_mutable_ptr, derLen);   // still available in 3.0
    if (der + derLen != der_mutable_ptr) {
        //if (result) {
        //    EVP_PKEY_free(result);
        //}
        throw_openssl(javaExceptionClass, "Extra key information");
    }
    if (!result.isInitialized()) {
        throw_openssl(javaExceptionClass, "Unable to parse key");
    }

    if (!checkKey(result)) {
        //EVP_PKEY_free(result);
        throw_openssl(javaExceptionClass, "Key fails check");
    }
    return result.take();
}

bool checkKey(EVP_PKEY const * key)
{
    int keyType = EVP_PKEY_base_id(key);
    int result = 0;

    BigNumObj p, q;
    ossl_auto<EVP_PKEY_CTX> ctx;

    switch (keyType) {
    case EVP_PKEY_RSA:
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
        if (!BN_is_zero(p) && !BN_is_zero(q)) 
        {    
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, const_cast<EVP_PKEY*>(key), NULL/*prop queue*/);
            result = EVP_PKEY_private_check(ctx);   
        } else {
            result = true;
        }
        break;
    case EVP_PKEY_EC:
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, const_cast<EVP_PKEY*>(key), NULL/*prop queue*/);
        result = EVP_PKEY_public_check(ctx);
        break;
    default:
        result = 1;
    }
    return result == 1;
}

}
