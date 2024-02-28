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

namespace AmazonCorrettoCryptoProvider {

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

        ctx.set(EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/));

        EVP_PKEY_keygen_init(ctx);

        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(jniCurve.native_str), 0);
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
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &gxBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &gyBN);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_ORDER, &orderBN);
        size_t field_type_length = 0;
        EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_FIELD_TYPE, field_type, sizeof(field_type), &field_type_length);

        if (strncmp(field_type, SN_X9_62_characteristic_two_field, field_type_length))
        {
            int m;
            EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_EC_CHAR2_M, &m);
            jint m2 = m;
            env->SetIntArrayRegion(mArr, 0, 1, &m2);
            env.rethrow_java_exception();
        }

        gxBN.toJavaArray(env, gxArr);
        gyBN.toJavaArray(env, gyArr);

        pBN.toJavaArray(env, pArr);
        aBN.toJavaArray(env, aArr);
        bBN.toJavaArray(env, bArr);

        cfBN.toJavaArray(env, cofactorArr);
        orderBN.toJavaArray(env, orderArr);


        ASN1_OBJECT* curve_ASN_obj = OBJ_txt2obj(jniCurve.native_str, 0/*search registered objects*/);

        // get nid
        int nid = OBJ_obj2nid(curve_ASN_obj);

        // get the numeric-dot notation OID
        char dot_notation_oid[80];

        if (!OBJ_obj2txt(dot_notation_oid, sizeof(dot_notation_oid), curve_ASN_obj, 1/*return OID in numeric-dot notation as a string, not the name*/)) {
            throw_openssl("Unable to get curve OID in numeric-dot notation");
        }

        jni_borrow oidBorrow = jni_borrow(env, java_buffer::from_array(env, oid), "curveNameToInfo");
        memcpy(oidBorrow.data(), dot_notation_oid, strlen(dot_notation_oid));
        oidBorrow.release();


        // get the DER encoded OID
        size_t serialized_oid_length = OBJ_length(curve_ASN_obj);

        char der_encoded_oid[80];

        der_encoded_oid[0] = 0x06;
        der_encoded_oid[1] = (char)serialized_oid_length;
        memcpy(&der_encoded_oid[2], OBJ_get0_data(curve_ASN_obj), serialized_oid_length);

        jni_borrow encodedOidBorrow = jni_borrow(env, java_buffer::from_array(env, encoded), "DER encoded curver OID");
        memcpy(encodedOidBorrow.data(), der_encoded_oid, serialized_oid_length + 2);
        encodedOidBorrow.release();

        return nid;
    }
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
    * Class:     com_amazon_corretto_crypto_provider_EcUtils
    * Method:    getCurveNames
    */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNames(JNIEnv* pEnv, jclass)
{
    try {
        raii_env env(pEnv);

        std::vector<EC_builtin_curve> curves;
        // Specify 0 as the max return count so no data is written, but we get the curve count
        size_t numCurves = EC_get_builtin_curves(curves.data(), 0);
        // Now that we know the number of curves to expect, resize and get the curve info from LC
        curves.resize(numCurves);
        numCurves = EC_get_builtin_curves(curves.data(), curves.size());
        if (numCurves > curves.size()) {
            // We get curve count from LC and resize accordingly, so we should never hit this.
            throw_openssl("Too many curves");
        }

        jobjectArray names = env->NewObjectArray(numCurves, env->FindClass("java/lang/String"), nullptr);
        for (size_t i = 0; i < numCurves; i++) {
            // NOTE: we return the "short name" (e.g. secp384r1) rather than the NIST name (e.g. "NIST P-384")
            env->SetObjectArrayElement(names, i, env->NewStringUTF(OBJ_nid2sn(curves[i].nid)));
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

        jni_borrow borrow = jni_borrow(env, java_buffer::from_array(env, encoded), "getCurveNameFromEncoded");
        size_t der_oid_len = borrow.len();
        size_t bin_oid_len = borrow[1];
        unsigned char bin_oid[80];
        memcpy(bin_oid, &borrow[2], bin_oid_len);

        string dot_oid = openssl_asn1_oid_bin2dot(bin_oid, bin_oid_len);

        ossl_auto<ASN1_OBJECT> dummy_obj = OBJ_txt2obj(dot_oid.c_str(), 1/*don't search registered objects*/);

        int nid = OBJ_obj2nid(dummy_obj);

        const char* sn = OBJ_nid2sn(nid);

        return pEnv->NewStringUTF(sn);
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