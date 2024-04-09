// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/md5.h>
//#define DIGEST_NAME       MD5
#define DIGEST_BLOCK_SIZE 64
//#include "hash_template.cpp.template"


#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"


using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getContextSize(JNIEnv*, jclass)
{
	return sizeof(MD5_CTX);
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_getHashSize(JNIEnv*, jclass)
{
	return MD5_DIGEST_LENGTH;
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_initContext(JNIEnv* pEnv, jclass, jbyteArray contextArray)
{
	try
	{
		raii_env env(pEnv);
		MD5_CTX ctx;
		java_buffer contextBuffer = java_buffer::from_array(env, contextArray);

		if (unlikely(contextBuffer.len() != sizeof(ctx)))
		{
			throw_java_ex(EX_ILLEGAL_ARGUMENT, "Bad context buffer size");
		}

		CHECK_OPENSSL(MD5_Init(&ctx));

		contextBuffer.put_bytes(env, reinterpret_cast<const uint8_t*>(&ctx), 0, sizeof(ctx));
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_updateContextByteArray(
	JNIEnv* pEnv,
	jclass,
	jbyteArray contextArray,
	jbyteArray dataArray,
	jint offset,
	jint length
)
{
	try
	{
		raii_env env(pEnv);

		bounce_buffer<MD5_CTX> ctx = bounce_buffer<MD5_CTX>::from_array(env, contextArray);

		try
		{
			java_buffer databuf = java_buffer::from_array(env, dataArray, offset, length);
			jni_borrow dataBorrow(env, databuf, "databuf");

			CHECK_OPENSSL(MD5_Update(ctx.ptr(), dataBorrow.data(), dataBorrow.len()));
		}
		catch (...)
		{
			ctx.zeroize();
			throw;
		}
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_finish(
	JNIEnv* pEnv,
	jclass,
	jbyteArray contextArray,
	jbyteArray digestArray,
	jint offset
)
{
	try
	{
		raii_env env(pEnv);
		bounce_buffer<MD5_CTX> ctx = bounce_buffer<MD5_CTX>::from_array(env, contextArray);

		java_buffer digestbuf = java_buffer::from_array(env, digestArray);
		jni_borrow digestBorrow(env, digestbuf, "digestbuf");

		int success = MD5_Final(digestBorrow.check_range(offset, MD5_DIGEST_LENGTH), ctx);

		ctx.zeroize();

		if (unlikely(!success))
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

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_updateNativeByteBuffer(
	JNIEnv* pEnv,
	jclass,
	jbyteArray contextArray,
	jobject dataDirectBuf
)
{
	try
	{
		raii_env env(pEnv);
		bounce_buffer<MD5_CTX> ctx = bounce_buffer<MD5_CTX>::from_array(env, contextArray);

		java_buffer dataBuf = java_buffer::from_direct(env, dataDirectBuf);
		jni_borrow dataBorrow(env, dataBuf, "dataBorrow");

		try
		{
			CHECK_OPENSSL(MD5_Update(ctx.ptr(), dataBorrow.data(), dataBorrow.len()));
		}
		catch (...)
		{
			ctx.zeroize();
			throw;
		}
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MD5Spi_fastDigest(
	JNIEnv* pEnv,
	jclass,
	jbyteArray digestArray,
	jbyteArray dataArray,
	jint dataLength
)
{
	try
	{
		raii_env env(pEnv);

		SecureBuffer<MD5_CTX, 1> ctx;
		const size_t scratchSize = DIGEST_BLOCK_SIZE;
		SecureBuffer<uint8_t, MD5_DIGEST_LENGTH> digest;

		if (unlikely(!MD5_Init(ctx)))
		{
			throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize context");
		}

		if (static_cast<size_t>(dataLength) > scratchSize)
		{
			java_buffer dataBuffer = java_buffer::from_array(env, dataArray, 0, dataLength);
			jni_borrow dataBorrow(env, dataBuffer, "data");
			if (unlikely(!MD5_Update(ctx, dataBorrow.data(), dataBorrow.len())))
			{
				throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to update context");
			}
		}
		else
		{
			SecureBuffer<uint8_t, scratchSize> scratch;
			env->GetByteArrayRegion(dataArray, 0, dataLength, reinterpret_cast<jbyte*>(scratch.buf));
			if (unlikely(!MD5_Update(ctx, scratch, dataLength)))
			{
				throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to udpate context");
			}
		}

		if (unlikely(!MD5_Final(digest, ctx)))
		{
			throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to finish digest");
		}
		env->SetByteArrayRegion(digestArray, 0, MD5_DIGEST_LENGTH, reinterpret_cast<const jbyte*>(digest.buf));
	}
	catch (java_ex& ex)
	{
		ex.throw_to_java(pEnv);
	}
}