// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

#include <sstream>
#include <vector>
#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <libloaderapi.h>


namespace AmazonCorrettoCryptoProvider {


    std::vector<int> fips_curves_nids{
    NID_secp224r1,
    NID_secp384r1,
    NID_secp521r1,
    NID_X9_62_prime192v1,
    NID_X9_62_prime256v1,
    NID_sect163k1,
    NID_sect163r2,
    NID_sect233k1,
    NID_sect233r1,
    NID_sect283k1,
    NID_sect283r1,
    NID_sect409k1,
    NID_sect409r1,
    NID_sect571k1,
    NID_sect571r1
    };

using std::string;
using std::stringstream;

static string openssl_asn1_oid_bin2dot(unsigned char* p, size_t length)
{
    stringstream ss1;

    for (size_t i = 0; i < length; i++)
    {
        if (i == 0)
        {
            unsigned char a = p[0];
            unsigned char a1 = a / 40;
            unsigned char a2 = a % 40;
            ss1 << (unsigned short)a1 << '.' << (unsigned short)a2 << '.';
        }
        else
        {
            unsigned char a = p[i];
            if ((a & 0x80) == 0)
            {
                ss1 << (unsigned short)a << '.';
            }
            else
            {
                unsigned long b = 0;
                a = a & 0x7f; // clear the highest bit in 'a'
                unsigned long c = (unsigned long)a; // c and b have the same length, the lowest 7 bits of c are meaningful
                b = b | c;
                i++;
                a = p[i];
                while ((a & 0x80) != 0)
                {
                    a = a & 0x7f;
                    c = (unsigned long)a;
                    b = b << 7;
                    b = b | c;
                    i++;
                    a = p[i];
                }
                c = (unsigned long)a;
                b = b << 7;
                b = b | c;
                ss1 << b << '.';
            }
        }
    }

    string s;
    ss1 >> s;
    size_t l = s.length();
    string final_string = s.substr(0, l - 1);

    return final_string;
}
}

using namespace AmazonCorrettoCryptoProvider;

#ifdef __cplusplus
extern "C" {
#endif
/*
* Class:     com_amazon_corretto_crypto_provider_EcUtils
* Method:    buildCurve
* Signature: (I)J
*/
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_buildGroup(JNIEnv* pEnv, jclass, jint nid)
{
    EC_GROUP* group;
    try {
        raii_env env(pEnv);

        if (unlikely(!(group = EC_GROUP_new_by_curve_name(nid)))) {
            throw_openssl("Unable to get group");
        }

        return reinterpret_cast<jlong>(group);
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
    * Class:     com_amazon_corretto_crypto_provider_EcUtils
    * Method:    freeCurve
    * Signature: (J)V
    */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_freeGroup(JNIEnv*, jclass, jlong group)
{
    EC_GROUP* ec_group = reinterpret_cast<EC_GROUP*>(group);
    EC_GROUP_free(ec_group);
}

/*
    * Class:     com_amazon_corretto_crypto_provider_EcUtils
    * Method:    curveNameToInfo
    * Signature: (Ljava/lang/String;[B[B[B[B[B[B[B)I
    */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_curveNameToInfo(JNIEnv* pEnv,
    jclass,
    jstring curveName,  // input
    jintArray mArr,     // exponent of 2^m field, output
    jbyteArray pArr,    // prime of prime field, output
    jbyteArray aArr,    // curve definition, output
    jbyteArray bArr,    // curve definition, output
    jbyteArray cofactorArr,  //  output
    jbyteArray gxArr,   // x-coordinate of public point, output
    jbyteArray gyArr,   // y-coordinate of public point, output
    jbyteArray orderArr,  // output
    jbyteArray oid,     // curve OID, output
    jbyteArray encoded)  // DER encoded curve OID, output
{
    try
    {
        raii_env env(pEnv);

        if (!curveName)
        {
            throw_java_ex(EX_NPE, "Curve name must not be null");
        }
        char field_type[80];

        jni_string jniCurve(env, curveName);

        ossl_auto<EVP_PKEY_CTX> ctx;
        ossl_auto<EVP_PKEY> pkey;

        ASN1_OBJECT* curve_ASN_obj = OBJ_txt2obj(jniCurve.native_str, 0/*search registered objects*/);

        // get nid
        int nid = OBJ_obj2nid(curve_ASN_obj);
        
        if (nid == NID_undef)
            return NID_undef;

        if (std::find(fips_curves_nids.begin(), fips_curves_nids.end(), nid) == std::end(fips_curves_nids))
        {
            // are you kidding me? give me a valid name but it's not a curve
            return NID_undef;
        }

        const char* curve_name_found = OBJ_nid2sn(nid);
        char curve_name_mutable[80];
        memset(curve_name_mutable, 0, sizeof(curve_name_mutable));

        memcpy(curve_name_mutable, curve_name_found, strlen(curve_name_found));

        ctx.set(EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/));

        EVP_PKEY_keygen_init(ctx);

        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve_name_mutable, 0);
        params[1] = OSSL_PARAM_construct_end();

        EVP_PKEY_CTX_set_params(ctx, params);

        EVP_PKEY_generate(ctx, &pkey);

        BigNumObj pBN;
        BigNumObj aBN;
        BigNumObj bBN;
        BigNumObj cfBN;
        BigNumObj gxBN;
        BigNumObj gyBN;
        BigNumObj orderBN;

        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_P, &pBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_A, &aBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_B, &bBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_COFACTOR, &cfBN);
        //EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &gxBN);
        //EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &gyBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_ORDER, &orderBN);
        size_t field_type_length = 0;
        EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_FIELD_TYPE, field_type, sizeof(field_type), &field_type_length);

        if (strncmp(field_type, SN_X9_62_characteristic_two_field, field_type_length) == 0)
        {
            int m;
            EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_EC_CHAR2_M, &m);
            jint m2 = m;
            env->SetIntArrayRegion(mArr, 0, 1, &m2);
            env.rethrow_java_exception();
        }

        size_t gen_buf_len = 0;
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0, &gen_buf_len);
        unsigned char* gen_buf = (unsigned char*)OPENSSL_malloc(gen_buf_len);
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_EC_GENERATOR, gen_buf, gen_buf_len, &gen_buf_len);
        size_t one_coordinate_len = (gen_buf_len - 1 ) / 2;
        
        // gxArra and gyArr are longer than what one coordinate needs, this is in big endian order, the more significant portion of gxArr and gyArr need to be left untouched

        java_buffer gx_buf = java_buffer::from_array(env, gxArr);
        java_buffer gy_buf = java_buffer::from_array(env, gyArr);

        size_t gx_buf_len = gx_buf.len();
        size_t gy_buf_len = gy_buf.len();

        size_t gx_lead_zero_len = gx_buf_len - one_coordinate_len;
        size_t gy_lead_zero_len = gy_buf_len - one_coordinate_len;

        gx_buf.put_bytes(env, (gen_buf + 1), gx_lead_zero_len, one_coordinate_len);
        gy_buf.put_bytes(env, (gen_buf + 1 + one_coordinate_len), gy_lead_zero_len, one_coordinate_len);

        //env->SetByteArrayRegion(gxArr, 0, one_coordinate_len, (jbyte*)(gen_buf + 1));
        //env->SetByteArrayRegion(gyArr, 0, one_coordinate_len, (jbyte*)(gen_buf + 1 + one_coordinate_len));

        //gxBN.toJavaArray(env, gxArr);
        //gyBN.toJavaArray(env, gyArr);

        pBN.toJavaArray(env, pArr);
        aBN.toJavaArray(env, aArr);
        bBN.toJavaArray(env, bArr);

        cfBN.toJavaArray(env, cofactorArr);
        orderBN.toJavaArray(env, orderArr);


        // get the numeric-dot notation OID
        char dot_notation_oid[80];

        int len = OBJ_obj2txt(dot_notation_oid, sizeof(dot_notation_oid), curve_ASN_obj, 1/*return OID in numeric-dot notation as a string, not the name*/);
        if (len <= 0)
        {
            // this function is not likely to fail if it's a valid curve.
            // Some curves don't have OID, for example: Oakley-EC2N-3 and Oakley-EC2N-4.
            // So if this function fails, I just assume the input curve is one of those that don't OID.
            // So I'm not throwing exception in case of failure.
            return nid;
        }

        //jni_borrow oidBorrow = jni_borrow(env, java_buffer::from_array(env, oid), "curveNameToInfo");
        jni_borrow oidBorrow{ env, java_buffer::from_array(env, oid), "curveNameToInfo" };
        memcpy(oidBorrow.data(), dot_notation_oid, strlen(dot_notation_oid));
        oidBorrow.release();
        

        // get the DER encoded OID
        size_t serialized_oid_length = OBJ_length(curve_ASN_obj);

        char der_encoded_oid[80];

        der_encoded_oid[0] = 0x06;
        der_encoded_oid[1] = (char)serialized_oid_length;
        memcpy(&der_encoded_oid[2], OBJ_get0_data(curve_ASN_obj), serialized_oid_length);

        //jni_borrow encodedOidBorrow = jni_borrow(env, java_buffer::from_array(env, encoded), "DER encoded curver OID");
        jni_borrow encodedOidBorrow = {env, java_buffer::from_array(env, encoded), "DER encoded curver OID"};
        memcpy(encodedOidBorrow.data(), der_encoded_oid, serialized_oid_length + 2);
        encodedOidBorrow.release();

        return nid;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

typedef size_t (get_builtin_curve_fp)(EC_builtin_curve*, size_t);

/*
    * Class:     com_amazon_corretto_crypto_provider_EcUtils
    * Method:    getCurveNames
    */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNames(JNIEnv* pEnv, jclass)
{
    try {
        raii_env env(pEnv);

        jobjectArray names = env->NewObjectArray(fips_curves_nids.size(), env->FindClass("java/lang/String"), nullptr);
        size_t i = 0;
        for (const int& nid : fips_curves_nids) {
            const char* sn = OBJ_nid2sn(nid);
            env->SetObjectArrayElement(names, i, env->NewStringUTF(sn));
            i++;
        }

        return names;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

/*
    * Class:     com_amazon_corretto_crypto_provider_EcUtils
    * Method:    getCurveNameFromEncoded
    * Signature: ([B)Ljava/lang/String
    */
JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNameFromEncoded(
    JNIEnv* pEnv, jclass, jbyteArray encoded)
{
    try {
        raii_env env(pEnv);

        size_t der_oid_len;
        size_t bin_oid_len;
        unsigned char bin_oid[80];
        memset(bin_oid, 0, sizeof(bin_oid));

        {
            jni_borrow curveNameDerBorrow = jni_borrow(env, java_buffer::from_array(env, encoded), "getCurveNameFromEncoded");
            der_oid_len = curveNameDerBorrow.len();
            if (der_oid_len < 3)
                throw_openssl("Unable to parse curve OID ASN.1");

            bin_oid_len = curveNameDerBorrow[1];
            memcpy(bin_oid, &curveNameDerBorrow[2], bin_oid_len);
        }
        string dot_oid = openssl_asn1_oid_bin2dot(bin_oid, bin_oid_len);

        ossl_auto<ASN1_OBJECT> dummy_obj = OBJ_txt2obj(dot_oid.c_str(), 1/*don't search registered objects*/);

        int nid = OBJ_obj2nid(dummy_obj);
        if (nid == NID_undef)
            throw_openssl("Unable to parse curve OID ASN.1");

        const char* sn = OBJ_nid2sn(nid);

        return env->NewStringUTF(sn);
        // original code has comment on why should *not* use raii_env, but I don't get it.
        // loader.cpp   Java_com_amazon_corretto_crypto_provider_Loader_getNativeLibraryVersio
        // similar scenario, that loader function uses raii_env.
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

#ifdef __cplusplus
}
#endif