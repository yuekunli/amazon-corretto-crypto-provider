/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_EvpHmac */

#ifndef _Included_com_amazon_corretto_crypto_provider_EvpHmac
#define _Included_com_amazon_corretto_crypto_provider_EvpHmac
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    getContextSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_getContextSize
  (JNIEnv *, jclass);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    updateCtxArray
 * Signature: ([B[BJ[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_updateCtxArray
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jlong, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    doFinal
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_doFinal
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpHmac
 * Method:    fastHmac
 * Signature: ([B[BJ[BII[B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmac_fastHmac
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jlong, jbyteArray, jint, jint, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
