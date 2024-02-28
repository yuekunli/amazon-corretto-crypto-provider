/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_SHA1Spi */

#ifndef _Included_com_amazon_corretto_crypto_provider_SHA1Spi
#define _Included_com_amazon_corretto_crypto_provider_SHA1Spi
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_SHA1Spi
 * Method:    fastDigest
 * Signature: ([B[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_fastDigest
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_SHA1Spi
 * Method:    initContext
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_initContext
  (JNIEnv *, jclass, jlongArray);

/*
 * Class:     com_amazon_corretto_crypto_provider_SHA1Spi
 * Method:    updateContextByteArray
 * Signature: ([B[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_updateContextByteArray
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_SHA1Spi
 * Method:    updateNativeByteBuffer
 * Signature: ([BLjava/nio/ByteBuffer;)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_updateNativeByteBuffer
  (JNIEnv *, jclass, jlong, jobject);

/*
 * Class:     com_amazon_corretto_crypto_provider_SHA1Spi
 * Method:    finish
 * Signature: ([B[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif
