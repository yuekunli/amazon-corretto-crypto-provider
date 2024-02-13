// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0


#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"

#include <openssl/sha.h> // define SHA1 digest length as "SHA_DIGEST_LENGTH"

#include <openssl/types.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define SHA1_DIGEST_LENGTH    SHA_DIGEST_LENGTH

#define FAST_PATH_INPUT_SIZE_LIMIT_FOR_USING_BORROW    64

using namespace AmazonCorrettoCryptoProvider;

/*
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getContextSize(JNIEnv*, jclass)
{
	return sizeof(MD5_CTX);
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getHashSize(JNIEnv*, jclass)
{
	return MD5_DIGEST_LENGTH;
}
*/

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_initContext(
	JNIEnv* pEnv,
	jclass,
	jlongArray ctxOut)
{
	EVP_MD_CTX* ctx = NULL;
	EVP_MD* md = NULL;

	try
	{
		raii_env env(pEnv);
		md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA1, NULL/*prop queue*/);
		ctx = EVP_MD_CTX_new();
		EVP_DigestInit(ctx, md);
		jlong tmpPtr = reinterpret_cast<jlong>(ctx);
		env->SetLongArrayRegion(ctxOut, 0, 1, &tmpPtr);
		EVP_MD_free(md);
	}
	catch (java_ex& ex)
	{
		if (md != NULL)
			EVP_MD_free(md);
		if (ctx != NULL)
			EVP_MD_CTX_free(ctx);
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_updateContextByteArray(
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

		try
		{
			java_buffer databuf = java_buffer::from_array(env, dataArray, offset, length);
			jni_borrow dataBorrow(env, databuf, "databuf");

			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		catch (...)
		{
			EVP_MD_CTX_free(ctx);
			throw;
		}
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_finish(
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

		//int success = MD5_Final(digestBorrow.check_range(offset, MD5_DIGEST_LENGTH), ctx);
		unsigned int len;
		int success = EVP_DigestFinal(ctx, digestBorrow.check_range(offset, SHA1_DIGEST_LENGTH), &len);

		EVP_MD_CTX_free(ctx);

		if (unlikely(success != 1))
		{
			digestBorrow.zeroize();
			throw_openssl();
		}
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_updateNativeByteBuffer(
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

		try
		{
			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		catch (...)
		{
			EVP_MD_CTX_free(ctx);
			throw;
		}
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_SHA1Spi_fastDigest(
	JNIEnv* pEnv,
	jclass,
	jbyteArray digestArray,
	jbyteArray dataArray,
	jint dataLength
)
{
	EVP_MD* md = NULL;
	EVP_MD_CTX* ctx = NULL;

	try
	{
		raii_env env(pEnv);
		md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA1, NULL/*prop queue*/);
		ctx = EVP_MD_CTX_new();
		EVP_DigestInit(ctx, md);

		const size_t scratchSize = FAST_PATH_INPUT_SIZE_LIMIT_FOR_USING_BORROW;
		SecureBuffer<uint8_t, SHA1_DIGEST_LENGTH> digest;

		if (static_cast<size_t>(dataLength) > scratchSize)
		{
			java_buffer dataBuffer = java_buffer::from_array(env, dataArray, 0, dataLength);
			jni_borrow dataBorrow(env, dataBuffer, "data");
			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		else
		{
			SecureBuffer<uint8_t, scratchSize> scratch;
			env->GetByteArrayRegion(dataArray, 0, dataLength, reinterpret_cast<jbyte*>(scratch.buf));
			EVP_DigestUpdate(ctx, scratch, dataLength);
		}
		unsigned int len;
		EVP_DigestFinal(ctx, digest, &len);

		env->SetByteArrayRegion(digestArray, 0, SHA1_DIGEST_LENGTH, reinterpret_cast<const jbyte*>(digest.buf));
		EVP_MD_free(md);
		EVP_MD_CTX_free(ctx);
	}
	catch (java_ex& ex)
	{
		if (md != NULL)
			EVP_MD_free(md);
		if (ctx != NULL)
			EVP_MD_CTX_free(ctx);
		ex.throw_to_java(pEnv);
	}
}