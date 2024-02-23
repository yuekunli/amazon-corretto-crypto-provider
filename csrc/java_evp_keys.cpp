// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>  // PKCS8_PRIV_KEY_INFO
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

using namespace AmazonCorrettoCryptoProvider;



// LiYK: The 2nd and 3rd functions can be retained, the OpenSSL APIs called in them are still available in OpenSSL 3.x
// The 4th and 5th functions call another API in this project, there is work needed in those deeper APIs



/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    releaseKey
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_releaseKey(JNIEnv*, jclass, jlong keyHandle)
{
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(keyHandle));
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePublicKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePublicKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        //OPENSSL_buffer_auto der;
        ossl_auto<unsigned char> der;
        // This next line allocates memory
        int derLen = i2d_PUBKEY(key, &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePrivateKey
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        //OPENSSL_buffer_auto der;
        ossl_auto<unsigned char>der;
        PKCS8_PRIV_KEY_INFO_auto pkcs8 = PKCS8_PRIV_KEY_INFO_auto::from(EVP_PKEY2PKCS8(key));
        CHECK_OPENSSL(pkcs8.isInitialized());

        // This next line allocates memory
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    pkcs82Evp
 * Signature: ([BI)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_pkcs82Evp(
    JNIEnv* pEnv, jclass, jbyteArray pkcs8der, jint nativeValue, jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto result;

        java_buffer pkcs8Buff = java_buffer::from_array(env, pkcs8der);
        size_t derLen = pkcs8Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, pkcs8Buff, "pkcs8Buff");
            result.set(der2EvpPrivateKey(borrow, derLen, shouldCheckPrivate, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result) != nativeValue) {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    x5092Evp
 * Signature: ([BI)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_x5092Evp(
    JNIEnv* pEnv, jclass, jbyteArray x509der, jint nativeValue)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto result;

        java_buffer x509Buff = java_buffer::from_array(env, x509der);
        size_t derLen = x509Buff.len();

        {
            jni_borrow borrow = jni_borrow(env, x509Buff, "x509Buff");
            result.set(der2EvpPublicKey(borrow, derLen, EX_INVALID_KEY_SPEC));
            if (EVP_PKEY_base_id(result) != nativeValue) {
                throw_java_ex(EX_INVALID_KEY_SPEC, "Incorrect key type");
            }
        }
        return reinterpret_cast<jlong>(result.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    ec2Evp
 * Signature: ([B[B[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp(   //  DELETE THIS
    JNIEnv* pEnv,
    jclass,
    jbyteArray sArr,  // private key (an integer)
    jbyteArray wxArr, // public key ( x coordinate of a point)
    jbyteArray wyArr, // public key ( y coordinate of a point)
    jbyteArray paramsArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        EC_KEY_auto ec;
        BN_CTX_auto bn_ctx;
        EC_POINT_auto point;

        {
            // Parse the parameters
            java_buffer paramsBuff = java_buffer::from_array(env, paramsArr);
            size_t paramsLength = paramsBuff.len();
            jni_borrow borrow(env, paramsBuff, "params");

            const unsigned char* derPtr = borrow.data();
            const unsigned char* derMutablePtr = derPtr;

            ec.set(d2i_ECParameters(NULL, &derMutablePtr, paramsLength));  // d2i_ECParameters deprecated in 3.0
            if (!ec.isInitialized()) {
                throw_openssl(EX_INVALID_KEY_SPEC, "Invalid parameters");
            }
            if (derPtr + paramsLength != derMutablePtr) {
                throw_openssl(EX_INVALID_KEY_SPEC, "Extra key information");
            }

            key.set(EVP_PKEY_new());
            if (!EVP_PKEY_set1_EC_KEY(key, ec)) {  // EVP_PKEY_set1_EC_KEY  deprecated in 3.0     EVP_PKEY_CTX_new_from_pkey  EVP_PKEY_fromdata
                throw_openssl(EX_INVALID_KEY_SPEC, "Could not convert to EVP_PKEY");
            }
        }

        // Set the key pieces
        {
            if (sArr) {
                BigNumObj s = BigNumObj::fromJavaArray(env, sArr);
                if (EC_KEY_set_private_key(ec, s) != 1) {  // EVP_KEY_set_private_key  deprecated in 3.0      OSSL_PKEY_PARAM_PRIV_KEY
                    throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set private key");
                }

                if (!wxArr || !wyArr) { 
                    
                    // LiYK: this block generates a public key based on the provided private key,
                    // EVP_POINT_mul is certainly doing a scala-point-multiplication
                    
                    // We have to calculate this ourselves.
                    // Otherwise, it will be taken care of later
                    const EC_GROUP* group = EC_KEY_get0_group(ec);
                    CHECK_OPENSSL(group);
                    CHECK_OPENSSL(point.set(EC_POINT_new(group)));
                    CHECK_OPENSSL(bn_ctx.set(BN_CTX_new()));

                    CHECK_OPENSSL(EC_POINT_mul(group, point, s, NULL, NULL, bn_ctx) == 1);

                    CHECK_OPENSSL(EC_KEY_set_public_key(ec, point) == 1);

                    unsigned int oldFlags = EC_KEY_get_enc_flags(ec);
                    EC_KEY_set_enc_flags(ec, oldFlags | EC_PKEY_NO_PUBKEY);
                }
                if (shouldCheckPrivate && !checkKey(key)) {
                    throw_openssl(EX_INVALID_KEY_SPEC, "Key fails check");
                }
            }

            if (wxArr && wyArr) {
                BigNumObj wx = BigNumObj::fromJavaArray(env, wxArr);
                BigNumObj wy = BigNumObj::fromJavaArray(env, wyArr);

                if (EC_KEY_set_public_key_affine_coordinates(ec, wx, wy) != 1) {
                    throw_openssl("Unable to set affine coordinates");
                }
            }
        }

        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}



// by inspecting the Java caller of this function, either sArr is present or (wxArr and wyArr) is present,
// never will both be present.
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp_ossl3(
    JNIEnv* pEnv,
    jclass,
    jbyteArray sArr,  // private key (an integer)
    jbyteArray wxArr, // public key ( x coordinate of a point)
    jbyteArray wyArr, // public key ( y coordinate of a point)
    jbyteArray paramsArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);

        java_buffer paramsBuff = java_buffer::from_array(env, paramsArr);
        size_t paramsLength = paramsBuff.len();
        jni_borrow borrow(env, paramsBuff, "params");

        const unsigned char* derPtr = borrow.data();
        const unsigned char* derMutablePtr = derPtr;

        EVP_PKEY* params_as_pkey = NULL;
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pkey_ctx = NULL;
        OSSL_DECODER_CTX* decoder_ctx = NULL;

        int selection = EVP_PKEY_KEY_PARAMETERS;
        const char* structure = "type-specific";
        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&params_as_pkey, "DER", structure, "EC", selection, NULL/*lib ctx*/, NULL/*prop queue*/);
        OSSL_DECODER_from_data(decoder_ctx, &derMutablePtr, &paramsLength);
        OSSL_DECODER_CTX_free(decoder_ctx);
        
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, params_as_pkey, NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pkey_ctx);

        OSSL_PARAM_BLD* incremental_params = NULL;
        OSSL_PARAM* params = NULL;

        incremental_params = OSSL_PARAM_BLD_new();

        if (sArr) {
            java_buffer priv_key_buff = java_buffer::from_array(env, sArr);
            size_t priv_key_buff_len = priv_key_buff.len();
            jni_borrow priv_key_borrow(env, priv_key_buff, "privkey");

            BIGNUM* priv_key = NULL;

            priv_key = BN_bin2bn(priv_key_borrow.data(), priv_key_buff_len, NULL);

            OSSL_PARAM_BLD_push_BN(incremental_params, OSSL_PKEY_PARAM_PRIV_KEY, priv_key);

            params = OSSL_PARAM_BLD_to_param(incremental_params);

            EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_KEYPAIR, params);

            EVP_PKEY_set_int_param(pkey, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0);

            if (shouldCheckPrivate)
            {
                int check_ret = EVP_PKEY_private_check(pkey_ctx);
                // check check_ret
            }

            // when building the parameters, BN is not copied, only its pointer is copied
            // after calling EVP_PKEY_fromdata, BN is copied to PKEY, at this point, I can free BN
            BN_free(priv_key);
        }

        if (wxArr && wyArr)
        {
            java_buffer pub_key_x = java_buffer::from_array(env, wxArr);
            size_t pub_key_x_len = pub_key_x.len();
            jni_borrow qx_borrow = jni_borrow(env, pub_key_x, "pubkeyx");

            java_buffer pub_key_y = java_buffer::from_array(env, wyArr);
            size_t pub_key_y_len = pub_key_y.len();
            jni_borrow qy_borrow = jni_borrow(env, pub_key_y, "pubkeyy");

            size_t pub_key_len = pub_key_x_len + pub_key_y_len + 1;
            unsigned char* ptr = (unsigned char*)malloc(pub_key_len);
            ptr[0] = 0x04; // uncompressed
            memcpy(ptr + 1, qx_borrow.data(), pub_key_x_len);
            memcpy(ptr + 1 + pub_key_x_len, qy_borrow.data(), pub_key_y_len);

            OSSL_PARAM_BLD_push_octet_string(incremental_params, OSSL_PKEY_PARAM_PUB_KEY, ptr, pub_key_len);
            OSSL_PARAM_BLD_push_utf8_string(incremental_params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "uncompressed", 0);
            params = OSSL_PARAM_BLD_to_param(incremental_params);

            EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

            free(ptr);
        }

        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(incremental_params);
        EVP_PKEY_free(params_as_pkey);
        EVP_PKEY_CTX_free(pkey_ctx);

        return reinterpret_cast<jlong>(pkey);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    getDerEncodedParams
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_getDerEncodedParams(   // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;

        int keyNid = EVP_PKEY_base_id(key);
        CHECK_OPENSSL(keyNid);

        int derLen = 0;

        switch (keyNid) {
        case EVP_PKEY_EC:
            derLen = i2d_ECParameters(EVP_PKEY_get0_EC_KEY(key), &der);
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported key type for parameters");
        }

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return result;
}



JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_getDerEncodedParams_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        //OPENSSL_buffer_auto der;
        ossl_auto<unsigned char>der;
        OSSL_ENCODER_CTX* ectx = NULL;
        int keyNid = EVP_PKEY_base_id(key);
        CHECK_OPENSSL(keyNid);

        int derLen = 0;
        switch (keyNid) {
        case EVP_PKEY_EC:
 
            int selection = EVP_PKEY_KEY_PARAMETERS;
            const char* structure = "type-specific";

            ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", structure, NULL/*prop queue*/);
            size_t derLen = 0;
            OSSL_ENCODER_to_data(ectx, &der, &derLen); // this function internally allocates memory on heap and makes "der" point to it.
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported key type for parameters");
        }
        CHECK_OPENSSL(derLen > 0);
        result = env->NewByteArray(derLen);
        env->SetByteArrayRegion(result, 0, derLen, der);
        OSSL_ENCODER_CTX_free(ectx);
        // der is wrapped in OPENSSL_buffer_auto whose destructor will take care of freeing memory
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return result;
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPublicKey
 * Method:    getPublicPointCoords
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPublicKey_getPublicPointCoords(   //  DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle, jbyteArray xArr, jbyteArray yArr)
{
    const EC_KEY* ecKey = NULL;
    const EC_GROUP* group = NULL;
    const EC_POINT* pubKey = NULL;
    BigNumObj xBN = bn_zero();
    BigNumObj yBN = bn_zero();

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(key));
        CHECK_OPENSSL(pubKey = EC_KEY_get0_public_key(ecKey));
        CHECK_OPENSSL(group = EC_KEY_get0_group(ecKey));

        CHECK_OPENSSL(EC_POINT_get_affine_coordinates(group, pubKey, xBN, yBN, NULL) == 1);

        bn2jarr(env, xArr, xBN);
        bn2jarr(env, yArr, yBN);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


// LiYK: See ec_kmgmt.c     function: key_to_params
// This function calls EC_POINT_get_affine_coordinates
// 
// ec_get_params (ec_kmgmt.c)
//    common_get_params (ec_kmgmt.c)
//       key_to_params
//
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPublicKey_getPublicPointCoords_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle, jbyteArray xArr, jbyteArray yArr)
{
    EVP_PKEY* key = NULL;
    BIGNUM* x = NULL, * y = NULL;
    try {
        raii_env env(pEnv);
        key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
        
        bn2jarr(env, xArr, x);
        bn2jarr(env, yArr, y);

        BN_free(x);
        BN_free(y);
    }
    catch (java_ex& ex) {
        if (x != NULL)
            BN_free(x);
        if (y != NULL)
            BN_free(y);
        ex.throw_to_java(pEnv);
    }
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpEcPrivateKey
 * Method:    getPrivateValue
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPrivateKey_getPrivateValue(   // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const EC_KEY* ecKey = NULL;
    const BIGNUM* sBN = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        CHECK_OPENSSL(ecKey = EVP_PKEY_get0_EC_KEY(key));
        CHECK_OPENSSL(sBN = EC_KEY_get0_private_key(ecKey));

        return bn2jarr(env, sBN);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPrivateKey_getPrivateValue_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    EVP_PKEY* key = NULL;
    BIGNUM* privKey = NULL;
    try {
        raii_env env(pEnv);
        key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &privKey);
        jbyteArray ret = bn2jarr(env, privKey);
        BN_free(privKey);
        return ret;
    }
    catch (java_ex& ex) {
        if (privKey != NULL)
            BN_free(privKey);
        ex.throw_to_java(pEnv);
        return NULL;
    }
}



/***********************************************/
/* RSA */

JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getModulus(   // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* n;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(n = RSA_get0_n(rsaKey));

        return bn2jarr(env, n);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getModulus_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    BIGNUM* n;
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
        return bn2jarr(env, n);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getPublicExponent(   // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* e;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(e = RSA_get0_e(rsaKey));

        return bn2jarr(env, e);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getPublicExponent_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    BIGNUM* e;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
     
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);

        return bn2jarr(env, e);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_getPrivateExponent(  // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* rsaKey;
    const BIGNUM* d;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        CHECK_OPENSSL(d = RSA_get0_d(rsaKey));

        return bn2jarr(env, d);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_getPrivateExponent_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    BIGNUM* d;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
   
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d);

        return bn2jarr(env, d);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_hasCrtParams(  // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    const RSA* r;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(key));

        const BIGNUM* dmp1;
        const BIGNUM* dmq1;
        const BIGNUM* iqmp;

        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
        if (!dmp1 || !dmq1 || !iqmp) {
            return false;
        }
        if (BN_is_zero(dmp1) || BN_is_zero(dmq1) || BN_is_zero(iqmp)) {
            return false;
        }
        return true;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}


JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_hasCrtParams_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        BIGNUM* dmp1;
        BIGNUM* dmq1;
        BIGNUM* iqmp;

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);
        
        if (!dmp1 || !dmq1 || !iqmp) {
            return false;
        }
        if (BN_is_zero(dmp1) || BN_is_zero(dmq1) || BN_is_zero(iqmp)) {
            return false;
        }
        return true;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}



// protected static native void getCrtParams(long ptr, byte[] crtCoefArr, byte[] expPArr, byte[] expQArr, byte[]
// primePArr, byte[] primeQArr, byte[] publicExponentArr, byte[] privateExponentArr);
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_getCrtParams(    // DELETE THIS
    JNIEnv* pEnv,
    jclass,
    jlong keyHandle,
    jbyteArray coefOut,
    jbyteArray dmPOut,
    jbyteArray dmQOut,
    jbyteArray primePOut,
    jbyteArray primeQOut,
    jbyteArray pubExpOut,
    jbyteArray privExpOut)
{
    const RSA* r;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        CHECK_OPENSSL(r = EVP_PKEY_get0_RSA(key));

        const BIGNUM* n;
        const BIGNUM* e;
        const BIGNUM* d;
        const BIGNUM* p;
        const BIGNUM* q;
        const BIGNUM* dmp1;
        const BIGNUM* dmq1;
        const BIGNUM* iqmp;

        RSA_get0_key(r, &n, &e, &d);
        RSA_get0_factors(r, &p, &q);
        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);

        bn2jarr(env, pubExpOut, e);
        bn2jarr(env, privExpOut, d);
        bn2jarr(env, primePOut, p);
        bn2jarr(env, primeQOut, q);
        bn2jarr(env, dmPOut, dmp1);
        bn2jarr(env, dmQOut, dmq1);
        bn2jarr(env, coefOut, iqmp);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_getCrtParams_ossl3(
    JNIEnv* pEnv,
    jclass,
    jlong keyHandle,
    jbyteArray coefOut,
    jbyteArray dmPOut,
    jbyteArray dmQOut,
    jbyteArray primePOut,
    jbyteArray primeQOut,
    jbyteArray pubExpOut,
    jbyteArray privExpOut)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        BIGNUM* e;
        BIGNUM* d;
        BIGNUM* p;
        BIGNUM* q;
        BIGNUM* dmp1;
        BIGNUM* dmq1;
        BIGNUM* iqmp;

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

        bn2jarr(env, pubExpOut, e);
        bn2jarr(env, privExpOut, d);
        bn2jarr(env, primePOut, p);
        bn2jarr(env, primeQOut, q);
        bn2jarr(env, dmPOut, dmp1);
        bn2jarr(env, dmQOut, dmq1);
        bn2jarr(env, coefOut, iqmp);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}



/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    rsa2Evp
 * Signature: ([B[B[B[B[B[B[B[B)J
 * modulus, publicExponentArr, privateExponentArr, crtCoefArr, expPArr, expQArr, primePArr, primeQArr
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_rsa2Evp(    //  DELETE THIS
    JNIEnv* pEnv,
    jclass,
    jbyteArray modulusArray,
    jbyteArray publicExponentArr,
    jbyteArray privateExponentArr,
    jbyteArray crtCoefArr,
    jbyteArray expPArr,
    jbyteArray expQArr,
    jbyteArray primePArr,
    jbyteArray primeQArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        RSA_auto rsa;

        if (unlikely(!rsa.set(RSA_new()))) {
            throw_openssl(EX_OOM, "Unable to create RSA object");
        }

        BigNumObj modulus = BigNumObj::fromJavaArray(env, modulusArray);
        // Java allows for weird degenerate keys with the public exponent being NULL.
        // We simulate this with zero.
        BigNumObj pubExp = bn_zero();
        if (publicExponentArr) {
            jarr2bn(env, publicExponentArr, pubExp);
        }

        if (privateExponentArr) {
            BigNumObj privExp = BigNumObj::fromJavaArray(env, privateExponentArr);

            int res;
            if (BN_is_zero(pubExp)) {
                // RSA blinding can't be performed without |e|; 0 indicates |e|'s absence.
                rsa->flags |= RSA_FLAG_NO_BLINDING;
                res = RSA_set0_key(rsa, modulus, NULL, privExp);
            } else {
                res = RSA_set0_key(rsa, modulus, pubExp, privExp);
            }

            if (res != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA values");
            }
            // RSA_set0_key takes ownership
            modulus.releaseOwnership();
            pubExp.releaseOwnership();
            privExp.releaseOwnership();
        } else {
            if (RSA_set0_key(rsa, modulus, pubExp, NULL) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA values");
            }
            // RSA_set0_key takes ownership
            modulus.releaseOwnership();
            pubExp.releaseOwnership();
        }

        if (primePArr && primeQArr) {
            BigNumObj p = BigNumObj::fromJavaArray(env, primePArr);
            BigNumObj q = BigNumObj::fromJavaArray(env, primeQArr);

            if (RSA_set0_factors(rsa, p, q) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA factors");
            }

            // RSA_set0_factors takes ownership
            p.releaseOwnership();
            q.releaseOwnership();
        }

        if (crtCoefArr && expPArr && expQArr) {
            BigNumObj iqmp = BigNumObj::fromJavaArray(env, crtCoefArr);
            BigNumObj dmp1 = BigNumObj::fromJavaArray(env, expPArr);
            BigNumObj dmq1 = BigNumObj::fromJavaArray(env, expQArr);

            if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA CRT values");
            }

            // RSA_set0_crt_params takes ownership
            iqmp.releaseOwnership();
            dmp1.releaseOwnership();
            dmq1.releaseOwnership();
        }

        key.set(EVP_PKEY_new());
        if (!key.isInitialized()) {
            throw_openssl(EX_OOM, "Unable to create EVP key");
        }

        if (unlikely(EVP_PKEY_set1_RSA(key, rsa) != 1)) {
            throw_openssl(EX_OOM, "Unable to assign RSA key");
        }
        // We can only check consistency if the CRT parameters are present
        if (shouldCheckPrivate && !!crtCoefArr && !checkKey(key)) {
            throw_openssl(EX_INVALID_KEY_SPEC, "Key fails check");
        }
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}


JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_rsa2Evp_ossl3(
    JNIEnv* pEnv,
    jclass,
    jbyteArray modulusArray,
    jbyteArray publicExponentArr,
    jbyteArray privateExponentArr,
    jbyteArray crtCoefArr,
    jbyteArray expPArr,
    jbyteArray expQArr,
    jbyteArray primePArr,
    jbyteArray primeQArr,
    jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* ctx = NULL;

        ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "RSA", NULL/*prop queue*/);

        OSSL_PARAM_BLD* paramBuild = NULL;
        OSSL_PARAM* params = NULL;

        paramBuild = OSSL_PARAM_BLD_new();

        BigNumObj e = BigNumObj::fromJavaArray(env, publicExponentArr);
        BigNumObj d = BigNumObj::fromJavaArray(env, privateExponentArr);
        BigNumObj n = BigNumObj::fromJavaArray(env, modulusArray);
        BigNumObj p = BigNumObj::fromJavaArray(env, primePArr);
        BigNumObj q = BigNumObj::fromJavaArray(env, primeQArr);
        BigNumObj iqmp = BigNumObj::fromJavaArray(env, crtCoefArr);
        BigNumObj dmp1 = BigNumObj::fromJavaArray(env, expPArr);
        BigNumObj dmq1 = BigNumObj::fromJavaArray(env, expQArr);

        OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_N, n);

        if (primePArr && primeQArr)
        {
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
        }

        if (crtCoefArr && expPArr && expQArr) {
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
        }

        if (publicExponentArr && !privateExponentArr) {

            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, e);
            params = OSSL_PARAM_BLD_to_param(paramBuild);
            EVP_PKEY_fromdata_init(ctx);
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        }
        else if (privateExponentArr) {

            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_D, d);

            /**
            * The RSA public exponent “e” value. This value must always be set 
            * when creating a raw key using EVP_PKEY_fromdata(3). Note that when
            * a decryption operation is performed, that this value is used for
            * blinding purposes to prevent timing attacks.
            */

            // Calculating public exponet from the private exponent and the modulus is impossible.
            // In order to do so, I need the primes (p and q) that multiply to n (n = pq)
            // NO_BLINDING is deprecated in 3.0, which means I must find the public exponent.
            
            // This is the most controversial part of this project, I'm manually setting public exponent to 65537

            BIGNUM* pub_exponent = NULL;
            if (!publicExponentArr)
            {
                static unsigned char pub_expo[] = {
                    0x01, 0x00, 0x01
                };

                pub_exponent = BN_bin2bn(pub_expo, 3, NULL);
                OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, pub_exponent);
            }

            params = OSSL_PARAM_BLD_to_param(paramBuild);
            EVP_PKEY_fromdata_init(ctx);
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
            BN_free(pub_exponent);
        }

        e.releaseOwnership();
        d.releaseOwnership();
        n.releaseOwnership();
        p.releaseOwnership();
        q.releaseOwnership();
        iqmp.releaseOwnership();
        dmp1.releaseOwnership();
        dmq1.releaseOwnership();

        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);

        return reinterpret_cast<jlong>(pkey);
    }
    catch (java_ex& ex)
    {
        ex.throw_to_java(pEnv);
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpRsaPrivateKey
 * Method:    encodeRsaPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_encodeRsaPrivateKey(  // DELETE THIS
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        OPENSSL_buffer_auto der;
        PKCS8_PRIV_KEY_INFO_auto pkcs8;

        const RSA* rsaKey = NULL;
        const BIGNUM* e = NULL;
        const BIGNUM* d = NULL;
        const BIGNUM* n = NULL;
        CHECK_OPENSSL(rsaKey = EVP_PKEY_get0_RSA(key));
        RSA_get0_key(rsaKey, &n, &e, &d);
        if (BN_null_or_zero(e)) {

            EVP_PKEY_auto stack_key;
            RSA_auto zeroed_rsa;

            // Key is lacking the public exponent so we must encode manually
            // Fortunately, this must be the most boring type of key (no params)

            // LiYK: If the public exponent is lacking, this block sets 'e' and factors and CRT parameters to zero, and then do PKCS8 encoding
            // Is this because these parameters may not be present in the encoding if I don't do this?
            // Having them as 0 in the encoded output is different than not having them at all???


            BIGNUM* zeroedE = BN_dup(e);
            if (nullptr == zeroedE) {
                CHECK_OPENSSL(zeroedE = BN_new());
            }

            CHECK_OPENSSL(zeroed_rsa.set(RSA_new()));
            if (!RSA_set0_key(zeroed_rsa, BN_dup(n), zeroedE, BN_dup(d))) {  // LiYK: this doesn't change anything, it just copies 'n' and 'd' and gives the same 'e' which is zero
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA components");
            }
            if (!RSA_set0_factors(zeroed_rsa, BN_new(), BN_new())) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA factors");
            }
            if (!RSA_set0_crt_params(zeroed_rsa, BN_new(), BN_new(), BN_new())) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set RSA CRT components");
            }
            stack_key.set(EVP_PKEY_new());
            CHECK_OPENSSL(stack_key.isInitialized());
            EVP_PKEY_set1_RSA(stack_key, zeroed_rsa);  // LiYK: It doesn't seem that this call eventually generates 'e' and those factors and CRT (Chinese Remainder Theorem) parameters

            CHECK_OPENSSL(pkcs8.set(EVP_PKEY2PKCS8(stack_key)));

        } else {
            // This is a normal key and we don't need to do anything special
            CHECK_OPENSSL(pkcs8.set(EVP_PKEY2PKCS8(key)));
        }

        // This next line allocates memory
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, 0, derLen, der);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}


JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_encodeRsaPrivateKey_ossl3(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(keyHandle);

        //OPENSSL_buffer_auto der;
        ossl_auto<unsigned char>der;
        BIGNUM* e = NULL, * d = NULL, * n = NULL;
        OSSL_ENCODER_CTX* encoder_ctx = NULL;
        size_t derLen = 0;

        int selection = EVP_PKEY_KEYPAIR;

        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);

#ifdef FILL_RSA_KEY_WHEN_PUBLIC_EXPONENT_IS_MISSING

        if (BN_null_or_zero(e))  // LiYK: I doubt this is necessary, if public exponent is missing, 
        {
            EVP_PKEY_CTX* filled_key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, pkey, NULL/*prop queue*/);
            EVP_PKEY* filled_pkey;
            OSSL_PARAM_BLD* paramBuild = NULL;
            OSSL_PARAM* params = NULL;
            BIGNUM* pub_exponent = NULL, *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

            paramBuild = OSSL_PARAM_BLD_new();
            static unsigned char pub_exponent_array[] = {
                0x01, 0x00, 0x01
            };
            pub_exponent = BN_bin2bn(pub_exponent_array, 3, NULL);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, pub_exponent);
            
            p = BN_new();
            q = BN_new();
            dmp1 = BN_new();
            dmq1 = BN_new();
            iqmp = BN_new();
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);

            params = OSSL_PARAM_BLD_to_param(paramBuild);

            EVP_PKEY_fromdata_init(filled_key_ctx);
            EVP_PKEY_fromdata(filled_key_ctx, &filled_pkey, EVP_PKEY_KEYPAIR, params);

            encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(filled_pkey, selection, "DER", NULL/*lib ctx*/, NULL/*prop queue*/);
            OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);

            BN_free(pub_exponent);
            BN_free(p);
            BN_free(q);
            BN_free(dmp1);
            BN_free(dmq1);
            BN_free(iqmp);
            EVP_PKEY_CTX_free(filled_key_ctx);
            EVP_PKEY_free(filled_pkey);
            OSSL_PARAM_BLD_free(paramBuild);
            OSSL_PARAM_free(params);
        }
        else
#endif

        {
            encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", NULL/*lib ctx*/, NULL/*prop queue*/);
            OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);
        }
        
        result = env->NewByteArray(derLen);
        env->SetByteArrayRegion(result, 0, derLen, der);
        OSSL_ENCODER_CTX_free(encoder_ctx);
        return result;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}
