// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
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

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    releaseKey
 */
extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_releaseKey(JNIEnv*, jclass, jlong keyHandle)
{
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(keyHandle));
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    encodePublicKey
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePublicKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        
        ossl_auto<unsigned char> der;
        
        int derLen = i2d_PUBKEY(key, &der);
        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }
        
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
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_encodePrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        
        ossl_auto<unsigned char>der;
        ossl_auto<PKCS8_PRIV_KEY_INFO> pkcs8;
        pkcs8 = EVP_PKEY2PKCS8(key);
        
        CHECK_OPENSSL(pkcs8.isInitialized());

        int derLen = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &der);

        CHECK_OPENSSL(derLen > 0);
        if (!(result = env->NewByteArray(derLen))) {
            throw_java_ex(EX_OOM, "Unable to allocate DER array");
        }

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
extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_pkcs82Evp(
    JNIEnv* pEnv, jclass, jbyteArray pkcs8der, jint nativeValue, jboolean shouldCheckPrivate)
{
    try {
        raii_env env(pEnv);
        ossl_auto<EVP_PKEY> result;

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
extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_x5092Evp(
    JNIEnv* pEnv, jclass, jbyteArray x509der, jint nativeValue)
{
    try {
        raii_env env(pEnv);
        ossl_auto<EVP_PKEY> result;

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
extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp(
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

        ossl_auto<EVP_PKEY> params_as_pkey;
        ossl_auto<EVP_PKEY> pkey;
        ossl_auto<EVP_PKEY_CTX> pkey_ctx;
        ossl_auto<OSSL_DECODER_CTX> decoder_ctx;

        int selection = EVP_PKEY_KEY_PARAMETERS;
        const char* structure = "type-specific";
        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&params_as_pkey, "DER", structure, "EC", selection, NULL/*lib ctx*/, NULL/*prop queue*/);
        OSSL_DECODER_from_data(decoder_ctx, &derMutablePtr, &paramsLength);
        OSSL_DECODER_CTX_free(decoder_ctx);
        
        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, params_as_pkey, NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pkey_ctx);

        ossl_auto<OSSL_PARAM_BLD> incremental_params;
        ossl_auto<OSSL_PARAM> params;

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
        return reinterpret_cast<jlong>(pkey.take());
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}


/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKey
 * Method:    getDerEncodedParams
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKey_getDerEncodedParams(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        
        ossl_auto<unsigned char>der;
        ossl_auto<OSSL_ENCODER_CTX> ectx = NULL;
        
        int keyNid = EVP_PKEY_base_id(key);
        CHECK_OPENSSL(keyNid);

        int selection = EVP_PKEY_KEY_PARAMETERS;
        const char* structure = "type-specific";
        size_t derLen = 0;

        switch (keyNid) {
        case EVP_PKEY_EC:
            ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", structure, NULL/*prop queue*/);
            OSSL_ENCODER_to_data(ectx, &der, &derLen); // this function internally allocates memory on heap and makes "der" point to it.
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported key type for parameters");
        }
        CHECK_OPENSSL(derLen > 0);
        result = env->NewByteArray(derLen);
        env->SetByteArrayRegion(result, 0, derLen, der);
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

// LiYK: See ec_kmgmt.c     function: key_to_params
// This function calls EC_POINT_get_affine_coordinates
// 
// ec_get_params (ec_kmgmt.c)
//    common_get_params (ec_kmgmt.c)
//       key_to_params
//

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPublicKey_getPublicPointCoords(
    JNIEnv* pEnv, jclass, jlong keyHandle, jbyteArray xArr, jbyteArray yArr)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        BigNumObj x , y;

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x);
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
        
        bn2jarr(env, xArr, x);
        bn2jarr(env, yArr, y);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpEcPrivateKey_getPrivateValue(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        BigNumObj privKey;

        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &privKey);
        jbyteArray ret = bn2jarr(env, privKey);

        return ret;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}



/***********************************************/
/* RSA */

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getModulus(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
        BigNumObj n;
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
        return bn2jarr(env, n);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaKey_getPublicExponent(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
 
        BigNumObj e;
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);

        return bn2jarr(env, e);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}


extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_getPrivateExponent(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);
 
        BigNumObj d;
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d);

        return bn2jarr(env, d);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_hasCrtParams(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    try {
        raii_env env(pEnv);

        EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(keyHandle);

        BigNumObj dmp1, dmq1, iqmp;

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


extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateCrtKey_getCrtParams(
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

        BigNumObj e, d, p, q, dmp1, dmq1, iqmp;

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
extern "C" JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_rsa2Evp(
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
        ossl_auto<EVP_PKEY> pkey;
        ossl_auto<EVP_PKEY_CTX> ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib ctx*/, "RSA", NULL/*prop queue*/);

        ossl_auto<OSSL_PARAM_BLD> paramBuild;
        ossl_auto<OSSL_PARAM> params;

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
        return reinterpret_cast<jlong>(pkey.take());
    }
    catch (java_ex& ex)
    {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

#define FILL_RSA_KEY_WHEN_PUBLIC_EXPONENT_IS_MISSING

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpRsaPrivateKey
 * Method:    encodeRsaPrivateKey
 * Signature: (J)[B
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpRsaPrivateKey_encodeRsaPrivateKey(
    JNIEnv* pEnv, jclass, jlong keyHandle)
{
    jbyteArray result = NULL;

    try {
        raii_env env(pEnv);

        EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(keyHandle);
        ossl_auto<unsigned char>der;

        ossl_auto<OSSL_ENCODER_CTX> encoder_ctx = NULL;
        size_t derLen = 0;

        int selection = EVP_PKEY_KEYPAIR;

#ifdef FILL_RSA_KEY_WHEN_PUBLIC_EXPONENT_IS_MISSING

        BigNumObj e, d, n;

        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n);

        if (BN_is_zero(e))
        {
            ossl_auto<EVP_PKEY_CTX> filled_key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, pkey, NULL/*prop queue*/);
            ossl_auto<EVP_PKEY> filled_pkey;
            ossl_auto<OSSL_PARAM_BLD> paramBuild;
            ossl_auto<OSSL_PARAM> params;
            BigNumObj pub_exponent;
            BigNumObj p, q, dmp1, dmq1, iqmp;

            paramBuild = OSSL_PARAM_BLD_new();
            static unsigned char pub_exponent_array[] = {
                0x01, 0x00, 0x01
            };
            *(&pub_exponent) = BN_bin2bn(pub_exponent_array, 3, NULL);
            OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_RSA_E, pub_exponent);
            
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

            //BN_free(pub_exponent);
        }
        else
#endif

        {
            encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", NULL/*lib ctx*/, NULL/*prop queue*/);
            OSSL_ENCODER_to_data(encoder_ctx, &der, &derLen);
        }
        
        result = env->NewByteArray(derLen);
        env->SetByteArrayRegion(result, 0, derLen, der);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return result;
}
