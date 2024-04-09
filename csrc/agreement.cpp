// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "buffer.h"
#include "env.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

namespace {

// Checks the openssl return value (and errorCode if needed)
// for various key-agreement methods and throws an appropriate
// C++-exception if necessary.
void checkAgreementResult(int result)
{
    if (result > 0) {
        return;
    }
    unsigned long errCode = drainOpensslErrors();
    std::string msg = formatOpensslError(errCode, "Unexpectected agreement error");

    if (errCode == 0x1c8000e2 // Invalid public key  //  ERR_PACK(ERR_LIB_PROV, 0, PROV_R_NOT_A_PUBLIC_KEY)
        || errCode == 0x1c8000cb // mismatching domain Parameters  // ERR_PACK(ERR_LIB_PROV, 0, PROV_R_MISMATCHING_DOMAIN_PARAMETERS)
    ) {
        throw_java_ex(EX_INVALID_KEY, msg);
    } else {
        throw_java_ex(EX_RUNTIME_CRYPTO, msg);
    }
}
} // namespace

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpKeyAgreement_agree(
    JNIEnv* pEnv, jclass clazz, jlong privateKeyPtr, jlong publicKeyPtr)
{
    jbyteArray result = NULL;
 
    try {
        raii_env env(pEnv);

        EVP_PKEY* privKey = reinterpret_cast<EVP_PKEY*>(privateKeyPtr);
        EVP_PKEY* pubKey = reinterpret_cast<EVP_PKEY*>(publicKeyPtr);
        ossl_auto<EVP_PKEY_CTX> pctx;

        pctx = EVP_PKEY_CTX_new_from_pkey(NULL/*lib ctx*/, privKey, NULL/*prop queue*/);
        
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            throw_openssl("Unable to initialize context");
        }
        checkAgreementResult(EVP_PKEY_derive_set_peer(pctx, pubKey));

        size_t resultLen = 0;
        std::vector<uint8_t> tmpResult;

        checkAgreementResult(EVP_PKEY_derive(pctx, NULL, &resultLen));
        tmpResult.resize(resultLen);

        size_t returnedLen = resultLen;
        checkAgreementResult(EVP_PKEY_derive(pctx, &tmpResult[0], &returnedLen));

        // OpenSSL may trim leading zeros (which is incorrect, so we left-pad it)
        result = env->NewByteArray(resultLen);
        if (!result) {
            throw_java_ex(EX_OOM, "Unable to allocate agreement array");
        }
        // This may throw, if it does we'll just keep the exception state as we return.
        env->SetByteArrayRegion(result, resultLen - returnedLen, returnedLen, (jbyte*)&tmpResult[0]);

        //EVP_PKEY_CTX_free(pctx);

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }

    return result;
}
