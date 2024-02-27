// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef KEYUTILS_H
#define KEYUTILS_H 1

#include "auto_free.h"
#include "env.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace AmazonCorrettoCryptoProvider {

// This class should generally not be used for new development
// as it has been replaced by the *_auto classes in auto_free.h
// The only time this class should be used is when you *need* to keep various EVP objects together.
// The only currently known *good* use for this class is tracking state when signing/verifying data.
//
// Since all but EVP_PKEY are stateful and likely to mutate while being used, this class is not threadsafe.
class EvpKeyContext {
public:
    EvpKeyContext() { } // Since we explicitly deleted constructors, the implicit one isn't generated for us.
    EVP_MD_CTX* getDigestCtx() { return digestCtx_.get(); }
    EVP_PKEY_CTX* getKeyCtx() { return keyCtx_.get(); }
    EVP_PKEY* getKey() { return key_.get(); }
    EVP_PKEY* get1Key()
    {
        EVP_PKEY_up_ref(key_);
        return getKey();
    }
    EVP_PKEY** getKeyPtr() { return key_.getAddressOfPtr(); }

    // If there was an old ctx, it is freed
    EVP_MD_CTX* setDigestCtx(EVP_MD_CTX* digestCtx)
    {
        digestCtx_.set(digestCtx);
        return getDigestCtx();
    }

    // If there was an old ctx, it is freed
    EVP_PKEY_CTX* setKeyCtx(EVP_PKEY_CTX* keyCtx)
    {
        keyCtx_.set(keyCtx);
        return getKeyCtx();
    }

    // If there was an old key, it is freed
    EVP_PKEY* setKey(EVP_PKEY* key)
    {
        key_.set(key);
        return getKey();
    }

    // Allocates a copy of this object on the heap and zeros
    // the pointers thus moving ownership of the contained objects
    // to the new copy of this EvpKeyContext.
    EvpKeyContext* moveToHeap()
    {
        EvpKeyContext* result = new EvpKeyContext();
        // Move the pointers and ownership to the new object.
        result->setKey(key_.take());
        result->setDigestCtx(digestCtx_.take());
        result->setKeyCtx(keyCtx_.take());

        return result;
    }

private:
    ossl_auto<EVP_MD_CTX> digestCtx_;
    ossl_auto<EVP_PKEY_CTX> keyCtx_;
    ossl_auto<EVP_PKEY> key_;

    // Disable copy & copy-assignment
    EvpKeyContext(const EvpKeyContext&) DELETE_IMPLICIT;
    EvpKeyContext& operator=(const EvpKeyContext&) DELETE_IMPLICIT;
};

EVP_PKEY* der2EvpPrivateKey(const unsigned char* der, const int derLen, const bool checkPrivateKey, const char* javaExceptionClass);
EVP_PKEY* der2EvpPublicKey(const unsigned char* der, const int derLen, const char* javaExceptionClass);
bool checkKey(const EVP_PKEY* key);

}

#endif
