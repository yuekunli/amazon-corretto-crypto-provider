// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "env.h"

#include <openssl/crypto.h>


// https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_VERSION_NUMBER.html
// 0xMNNFFPPS : major minor fix patch status
// 0x1010107f == v1.1.1g release
#define LIBCRYPTO_MAJOR_MINOR_VERSION_MASK 0xFFF00000

using namespace AmazonCorrettoCryptoProvider;

namespace {

void initialize()
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
}

}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    initialize();
    return JNI_VERSION_1_4;
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_isFipsMode(JNIEnv*, jclass)
{
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_Loader_getNativeLibraryVersion(JNIEnv* pEnv, jclass)
{
    try {
        raii_env env(pEnv);

        return env->NewStringUTF(STRINGIFY(PROVIDER_VERSION_STRING));
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return NULL;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_Loader_validateLibcryptoVersion(
    JNIEnv* pEnv, jclass, jboolean jFuzzyMatch)
{
    bool fuzzyMatch = (jFuzzyMatch == JNI_TRUE);

    try {
        unsigned long libcrypto_compiletime_version = OPENSSL_VERSION_NUMBER;
        unsigned long libcrypto_runtime_version = OpenSSL_version_num();

        if (fuzzyMatch) {
            libcrypto_compiletime_version &= LIBCRYPTO_MAJOR_MINOR_VERSION_MASK;
            libcrypto_runtime_version &= LIBCRYPTO_MAJOR_MINOR_VERSION_MASK;
        }

        if (libcrypto_compiletime_version != libcrypto_runtime_version) {
            char accp_loader_exception_msg[256] = { 0 };
            snprintf(accp_loader_exception_msg, sizeof(accp_loader_exception_msg),
                "Runtime libcrypto version does not match compile-time version. Expected: 0x%08lX , Actual: 0x%08lX",
                libcrypto_compiletime_version, libcrypto_runtime_version);
            throw java_ex(EX_RUNTIME_CRYPTO, accp_loader_exception_msg);
        }
        return JNI_TRUE;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return JNI_FALSE;
}
