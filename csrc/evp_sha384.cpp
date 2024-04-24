// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "buffer.h"
#include "env.h"
#include "auto_free.h"
#include "util.h"

#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define FAST_PATH_INPUT_SIZE_LIMIT_FOR_USING_BORROW    128

using namespace AmazonCorrettoCryptoProvider;

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_initContext(
	JNIEnv* pEnv,
	jclass,
	jlongArray ctxOut)
{
	try
	{
		raii_env env(pEnv);
		ossl_auto<EVP_MD_CTX> ctx;
		ossl_auto<EVP_MD> md;
		md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
		ctx = EVP_MD_CTX_new();
		EVP_DigestInit(ctx, md);
		jlong tmpPtr = reinterpret_cast<jlong>(ctx.take());
		env->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_updateContextByteArray(
	JNIEnv* pEnv,
	jclass,
	jlong ctxPtr,
	jbyteArray dataArray,
	jint offset,
	jint length
)
{
	try
	{
		raii_env env(pEnv);

		EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);

		java_buffer databuf = java_buffer::from_array(env, dataArray, offset, length);
		jni_borrow dataBorrow(env, databuf, "databuf");

		EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_finish(
	JNIEnv* pEnv,
	jclass,
	jlong ctxPtr,
	jbyteArray digestArray,
	jint offset
)
{
	try
	{
		raii_env env(pEnv);

		EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);

		java_buffer digestbuf = java_buffer::from_array(env, digestArray);
		jni_borrow digestBorrow(env, digestbuf, "digestbuf");

		unsigned int len;
		int success = EVP_DigestFinal(ctx, digestBorrow.check_range(offset, SHA384_DIGEST_LENGTH), &len);
		if (unlikely(success != 1))
		{
			digestBorrow.zeroize();
			throw_openssl();
		}
		EVP_MD* md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
		EVP_DigestInit(ctx, md);
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_updateNativeByteBuffer(
	JNIEnv* pEnv,
	jclass,
	jlong ctxPtr,
	jobject dataDirectBuf
)
{
	try
	{
		raii_env env(pEnv);
		EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);

		java_buffer dataBuf = java_buffer::from_direct(env, dataDirectBuf);
		jni_borrow dataBorrow(env, dataBuf, "dataBorrow");

		EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_resetContext(
	JNIEnv* pEnv,
	jclass,
	jlong ctxPtr)
{
	try {
		raii_env env(pEnv);
		EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);
		EVP_MD_CTX_reset(ctx);
		EVP_MD* md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
		EVP_DigestInit(ctx, md);
	}
	catch (java_ex& ex) {
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_cloneContext(
	JNIEnv* pEnv,
	jclass,
	jlong ctxPtr,
	jlongArray ctxOut)
{
	try {
		raii_env env(pEnv);

		EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);

		EVP_MD_CTX* ctxDup = EVP_MD_CTX_new();

		int ret = EVP_MD_CTX_copy(ctxDup, ctx);
		if (ret == 1)
		{
			jlong tmpPtr = reinterpret_cast<jlong>(ctxDup);
			env->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
		}
		else
		{
			EVP_MD_CTX_free(ctxDup);
			throw_openssl();
		}
	}
	catch (java_ex& ex) {
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA384Spi_fastDigest(
	JNIEnv* pEnv,
	jclass,
	jbyteArray digestArray,
	jbyteArray dataArray,
	jint dataOffset,
	jint dataLength
)
{
	try
	{
		raii_env env(pEnv);

		ossl_auto<EVP_MD> md;
		ossl_auto<EVP_MD_CTX> ctx;

		md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
		ctx = EVP_MD_CTX_new();
		EVP_DigestInit(ctx, md);

		const size_t scratchSize = FAST_PATH_INPUT_SIZE_LIMIT_FOR_USING_BORROW;
		SecureBuffer<uint8_t, SHA384_DIGEST_LENGTH> digest;

		if (static_cast<size_t>(dataLength) > scratchSize)
		{
			java_buffer dataBuffer = java_buffer::from_array(env, dataArray, dataOffset, dataLength);
			jni_borrow dataBorrow(env, dataBuffer, "data");
			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		else
		{
			SecureBuffer<uint8_t, scratchSize> scratch;
			env->GetByteArrayRegion(dataArray, dataOffset, dataLength, reinterpret_cast<jbyte*>(scratch.buf));
			EVP_DigestUpdate(ctx, scratch, dataLength);
		}
		unsigned int len;
		EVP_DigestFinal(ctx, digest, &len);

		env->SetByteArrayRegion(digestArray, 0, SHA384_DIGEST_LENGTH, reinterpret_cast<const jbyte*>(digest.buf));
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

#ifdef __cplusplus
}
#endif