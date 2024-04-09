#include "buffer.h"
#include "env.h"
#include "util.h"
#include "auto_free.h"

#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

extern enum DIGESTTYPE {
	_MD5 = 0,
	_SHA1,
	_SHA256,
	_SHA384,
	_SHA512
};

namespace {
	char md5_name[] = "MD5";
	char sha1_name[] = "SHA1";
	char sha256_name[] = "SHA256";
	char sha384_name[] = "SHA384";
	char sha512_name[] = "SHA512";
}

#ifdef __cplusplus
extern "C" {
#endif
	JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EvpHmacSinglePass_singlePassHmac(
		JNIEnv* pEnv,
		jclass clazz,
		jint digestType,
		jbyteArray outputArr,
		jbyteArray keyArr,
		jbyteArray inputArr,
		jint input_offset,
		jint input_len)
	{
		try {
			raii_env env(pEnv);

			ossl_auto<EVP_MAC_CTX> ctx;
			
			
			java_buffer outputBuf = java_buffer::from_array(env, outputArr);

			
			OSSL_PARAM params[2], * p = params;
			ossl_auto<EVP_MAC> mac;

			mac = EVP_MAC_fetch(NULL/*lib context*/, "HMAC", NULL/*prop queue*/);
			ctx = EVP_MAC_CTX_new(mac);
			switch (digestType)
			{
			
			case DIGESTTYPE::_SHA1:
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha1_name, sizeof(sha1_name));
				break;
			case DIGESTTYPE::_SHA256:
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha256_name, sizeof(sha256_name));
				break;
			case DIGESTTYPE::_SHA384:
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha384_name, sizeof(sha384_name));
				break;
			case DIGESTTYPE::_SHA512:
				*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, sha512_name, sizeof(sha512_name));
				break;
			}
			*p = OSSL_PARAM_construct_end();

			{
				java_buffer keyBuf = java_buffer::from_array(env, keyArr);
				jni_borrow key(env, keyBuf, "key");
				EVP_MAC_init(ctx, key.data(), key.len(), params);
			}

			{
				java_buffer inputBuf = java_buffer::from_array(env, inputArr, input_offset, input_len);
				jni_borrow input(env, inputBuf, "input");
				if (EVP_MAC_update(ctx, input.data(), input.len()) != 1)
					throw_openssl("Fail to send input to HMAC");
			}

			uint8_t tempBuf[EVP_MAX_MD_SIZE];
			size_t macSize = EVP_MAX_MD_SIZE;
			EVP_MAC_final(ctx, NULL, &macSize, 0);

			if (EVP_MAC_final(ctx, tempBuf, &macSize, macSize) != 1)
				throw_openssl("Fail to finalize HMAC");

			outputBuf.put_bytes(env, tempBuf, 0, macSize);
		}
		catch (java_ex* ex) {
			ex->throw_to_java(pEnv);
		}
	}

#ifdef __cplusplus
}
#endif