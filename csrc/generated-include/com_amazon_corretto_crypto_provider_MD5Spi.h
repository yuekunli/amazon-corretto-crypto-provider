/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_MD5Spi */

#ifndef _Included_com_amazon_corretto_crypto_provider_MD5Spi
#define _Included_com_amazon_corretto_crypto_provider_MD5Spi
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    fastDigest
 * Signature: ([B[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_fastDigest
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    getHashSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getHashSize
  (JNIEnv *, jclass);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    getContextSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getContextSize
  (JNIEnv *, jclass);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    initContext
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_initContext
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    updateContextByteArray
 * Signature: ([B[BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_updateContextByteArray
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    updateNativeByteBuffer
 * Signature: ([BLjava/nio/ByteBuffer;)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_updateNativeByteBuffer
  (JNIEnv *, jclass, jbyteArray, jobject);

/*
 * Class:     com_amazon_corretto_crypto_provider_MD5Spi
 * Method:    finish
 * Signature: ([B[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_finish
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif
