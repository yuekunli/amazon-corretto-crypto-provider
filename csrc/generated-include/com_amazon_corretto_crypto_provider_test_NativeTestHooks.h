/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_test_NativeTestHooks */

#ifndef _Included_com_amazon_corretto_crypto_provider_test_NativeTestHooks
#define _Included_com_amazon_corretto_crypto_provider_test_NativeTestHooks
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    throwException
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_throwException
  (JNIEnv *, jclass);

/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    getBytes
 * Signature: ([BIIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_getBytes
  (JNIEnv *, jclass, jbyteArray, jint, jint, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    putBytes
 * Signature: ([BIIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_putBytes
  (JNIEnv *, jclass, jbyteArray, jint, jint, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    getBytesLocked
 * Signature: ([BIIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_getBytesLocked
  (JNIEnv *, jclass, jbyteArray, jint, jint, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    putBytesLocked
 * Signature: ([BIIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_putBytesLocked
  (JNIEnv *, jclass, jbyteArray, jint, jint, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_test_NativeTestHooks
 * Method:    borrowCheckRange
 * Signature: ([BIIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_borrowCheckRange
  (JNIEnv *, jclass, jbyteArray, jint, jint, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
