/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_EvpKeyFactory */

#ifndef _Included_com_amazon_corretto_crypto_provider_EvpKeyFactory
#define _Included_com_amazon_corretto_crypto_provider_EvpKeyFactory
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    pkcs82Evp
 * Signature: ([BIZ)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_pkcs82Evp
  (JNIEnv *, jclass, jbyteArray, jint, jboolean);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    x5092Evp
 * Signature: ([BI)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_x5092Evp
  (JNIEnv *, jclass, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    rsa2Evp
 * Signature: ([B[B[B[B[B[B[B[BZ)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_rsa2Evp
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jboolean);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpKeyFactory
 * Method:    ec2Evp
 * Signature: ([B[B[B[BZ)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyFactory_ec2Evp
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jboolean);

#ifdef __cplusplus
}
#endif
#endif
