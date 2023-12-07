/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_amazon_corretto_crypto_provider_AesXtsSpi */

#ifndef _Included_com_amazon_corretto_crypto_provider_AesXtsSpi
#define _Included_com_amazon_corretto_crypto_provider_AesXtsSpi
#ifdef __cplusplus
extern "C" {
#endif
#undef com_amazon_corretto_crypto_provider_AesXtsSpi_BLOCK_SIZE_IN_BYTES
#define com_amazon_corretto_crypto_provider_AesXtsSpi_BLOCK_SIZE_IN_BYTES 16L
#undef com_amazon_corretto_crypto_provider_AesXtsSpi_TWEAK_SIZE_IN_BYTES
#define com_amazon_corretto_crypto_provider_AesXtsSpi_TWEAK_SIZE_IN_BYTES 16L
#undef com_amazon_corretto_crypto_provider_AesXtsSpi_KEY_SIZE_IN_BYTES
#define com_amazon_corretto_crypto_provider_AesXtsSpi_KEY_SIZE_IN_BYTES 64L
#undef com_amazon_corretto_crypto_provider_AesXtsSpi_MINIMUM_INPUT_SIZE_FOR_AES_XTS
#define com_amazon_corretto_crypto_provider_AesXtsSpi_MINIMUM_INPUT_SIZE_FOR_AES_XTS 16L
/*
 * Class:     com_amazon_corretto_crypto_provider_AesXtsSpi
 * Method:    enc
 * Signature: ([B[BII[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_enc
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_AesXtsSpi
 * Method:    encSameBuffer
 * Signature: ([B[BIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_encSameBuffer
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_AesXtsSpi
 * Method:    dec
 * Signature: ([B[BII[BI)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_dec
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_AesXtsSpi
 * Method:    decSameBuffer
 * Signature: ([B[BIII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AesXtsSpi_decSameBuffer
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jint);

#ifdef __cplusplus
}
#endif
#endif
