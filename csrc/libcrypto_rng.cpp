// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _DEFAULT_SOURCE // for getentropy

#include <openssl/rand.h>

#include "buffer.h"
#include "env.h"

using namespace AmazonCorrettoCryptoProvider;

bool libCryptoRngGenerateRandomBytes(uint8_t* buf, int len) noexcept
{
    int success = RAND_bytes(buf, len);

    return (success == 1);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_LibCryptoRng
 * Method:    generate
 * Signature: ([BII)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_LibCryptoRng_generate(
    JNIEnv* pEnv, jclass, jbyteArray byteArray, jint offset, jint length)
{
    try {
        raii_env env(pEnv);

        java_buffer byteBuffer = java_buffer::from_array(env, byteArray, offset, length);
        jni_borrow bytes(env, byteBuffer, "bytes");

        if (!libCryptoRngGenerateRandomBytes(bytes, length)) {
            bytes.zeroize();
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Failed to generate random bytes");
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}
