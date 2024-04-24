// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "buffer.h"
#include "env.h"
#include "auto_free.h"
#include "util.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define SHA1_DIGEST_LENGTH    SHA_DIGEST_LENGTH

enum DIGESTTYPE
{
	_MD5 = 0,
	_SHA1,
	_SHA256,
	_SHA384,
	_SHA512
};

using namespace AmazonCorrettoCryptoProvider;

#ifdef __cplusplus
extern "C" {
#endif

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_initContext(
		JNIEnv* pEnv,
		jclass,
		jint digestType,
		jlongArray ctxOut)
	{
		try
		{
			raii_env env(pEnv);
			ossl_auto<EVP_MD_CTX> ctx;
			ossl_auto<EVP_MD> md;
			switch (digestType)
			{
			case DIGESTTYPE::_MD5:
				md = EVP_MD_fetch(NULL/*lib context*/, OSSL_DIGEST_NAME_MD5, NULL/*prop queue*/);
				break;
			case DIGESTTYPE::_SHA1:
				md = EVP_MD_fetch(NULL/*lib context*/, OSSL_DIGEST_NAME_SHA1, NULL/*prop queue*/);
				break;
			case DIGESTTYPE::_SHA256:
				md = EVP_MD_fetch(NULL/*lib context*/, OSSL_DIGEST_NAME_SHA2_256, NULL/*prop queue*/);
				break;
			case DIGESTTYPE::_SHA384:
				md = EVP_MD_fetch(NULL/*lib context*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
				break;
			case DIGESTTYPE::_SHA512:
				md = EVP_MD_fetch(NULL/*lib context*/, OSSL_DIGEST_NAME_SHA2_512, NULL/*prop queue*/);
				break;
			}

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

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_cloneContext(
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

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_updateInputArray(
		JNIEnv* pEnv,
		jclass,
		jlong ctxPtr,
		jbyteArray dataArray,
		jint offset,
		jint length)
	{
		try {
			raii_env env(pEnv);
			EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);
			java_buffer databuf = java_buffer::from_array(env, dataArray, offset, length);
			jni_borrow dataBorrow(env, databuf, "databuf");

			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		catch (java_ex& ex) {
			ex.throw_to_java(pEnv);
		}
	}

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_updateInputBuffer(
		JNIEnv* pEnv,
		jclass,
		jlong ctxPtr,
		jobject dataDirectBuf)
	{
		try {
			raii_env env(pEnv);
			EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);

			java_buffer dataBuf = java_buffer::from_direct(env, dataDirectBuf);
			jni_borrow dataBorrow(env, dataBuf, "dataBorrow");

			EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
		}
		catch (java_ex& ex) {
			ex.throw_to_java(pEnv);
		}
	}

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_finish(
		JNIEnv* pEnv,
		jclass,
		jlong ctxPtr,
		jbyteArray digestArray,
		jint offset)
	{
		try {
			raii_env env(pEnv);
			EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);
			java_buffer digestbuf = java_buffer::from_array(env, digestArray);
			jni_borrow digestBorrow(env, digestbuf, "digestbuf");
			int expected_size = EVP_MD_CTX_get_size(ctx);
			unsigned int len;
			int ret = EVP_DigestFinal(ctx, digestBorrow.check_range(offset, expected_size), &len);
			EVP_MD_CTX_free(ctx);
			if (unlikely(ret != 1))
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

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_reset(
		JNIEnv* pEnv,
		jclass,
		jlong ctxPtr)
	{
		try {
			raii_env env(pEnv);
			EVP_MD_CTX* ctx = reinterpret_cast<EVP_MD_CTX*>(ctxPtr);
			EVP_MD_CTX_reset(ctx);
		}
		catch (java_ex& ex) {
			ex.throw_to_java(pEnv);
		}
	}

	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpMessageDigestIncremental_singlePassDigest(
		JNIEnv* pEnv,
		jclass,
		jint digestType,
		jbyteArray outputArray,
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

			SecureBuffer<uint8_t, MD5_DIGEST_LENGTH> output_md5;
			SecureBuffer<uint8_t, SHA1_DIGEST_LENGTH> output_sha1;
			SecureBuffer<uint8_t, SHA256_DIGEST_LENGTH> output_sha256;
			SecureBuffer<uint8_t, SHA384_DIGEST_LENGTH> output_sha384;
			SecureBuffer<uint8_t, SHA512_DIGEST_LENGTH> output_sha512;

			SecureBuffer<uint8_t, 64> scratch_buffer_small;
			SecureBuffer<uint8_t, 128> scratch_buffer_big;

			uint8_t* output_ptr;
			uint8_t* scratch_buffer_ptr;
			size_t output_len;
			size_t scratchSize;

			switch (digestType)
			{
			case DIGESTTYPE::_MD5:
				md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_MD5, NULL/*prop queue*/);
				output_ptr = output_md5.buf;
				scratch_buffer_ptr = scratch_buffer_small.buf;
				output_len = MD5_DIGEST_LENGTH;
				scratchSize = 64;
				break;
			case DIGESTTYPE::_SHA1:
				md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA1, NULL/*prop queue*/);
				output_ptr = output_sha1.buf;
				scratch_buffer_ptr = scratch_buffer_small.buf;
				output_len = SHA1_DIGEST_LENGTH;
				scratchSize = 64;
				break;
			case DIGESTTYPE::_SHA256:
				md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_256, NULL/*prop queue*/);
				output_ptr = output_sha256.buf;
				scratch_buffer_ptr = scratch_buffer_small.buf;
				output_len = SHA256_DIGEST_LENGTH;
				scratchSize = 64;
				break;
			case DIGESTTYPE::_SHA384:
				md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_384, NULL/*prop queue*/);
				output_ptr = output_sha384.buf;
				scratch_buffer_ptr = scratch_buffer_big.buf;
				output_len = SHA384_DIGEST_LENGTH;
				scratchSize = 128;
				break;
			case DIGESTTYPE::_SHA512:
				md = EVP_MD_fetch(NULL/*lib ctx*/, OSSL_DIGEST_NAME_SHA2_512, NULL/*prop queue*/);
				output_ptr = output_sha512.buf;
				scratch_buffer_ptr = scratch_buffer_big.buf;
				output_len = SHA512_DIGEST_LENGTH;
				scratchSize = 128;
				break;
			default:
				throw_java_ex(EX_ILLEGAL_ARGUMENT, "unsupported message digest type");
				break;
			}
			
			ctx = EVP_MD_CTX_new();
			EVP_DigestInit(ctx, md);


			if (static_cast<size_t>(dataLength) > scratchSize)
			{
				java_buffer dataBuffer = java_buffer::from_array(env, dataArray, dataOffset, dataLength);
				jni_borrow dataBorrow(env, dataBuffer, "data");
				EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len());
			}
			else
			{
				env->GetByteArrayRegion(dataArray, dataOffset, dataLength, reinterpret_cast<jbyte*>(scratch_buffer_ptr));
				EVP_DigestUpdate(ctx, scratch_buffer_ptr, dataLength);
			}
			unsigned int len;
			EVP_DigestFinal(ctx, output_ptr, &len);

			env->SetByteArrayRegion(outputArray, 0, output_len, reinterpret_cast<const jbyte*>(output_ptr));
		}
		catch (java_ex& ex)
		{
			ex.throw_to_java(pEnv);
		}
	}

#ifdef __cplusplus
}
#endif