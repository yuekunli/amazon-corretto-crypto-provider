// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AUTO_FREE_H
#define AUTO_FREE_H

#include "jni_md.h"

#include "env.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/asn1.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>

using namespace AmazonCorrettoCryptoProvider;

template<typename T>
class ossl_auto
{
private:
    T* ptr;
    
    void move(ossl_auto<T>& other)
    {
        set(other.take());
    }

public:

    // default constructor
    ossl_auto() :ptr(NULL) {}

    // delete copy constructor and copy assignment
    ossl_auto(const ossl_auto<T>&) = delete;
    ossl_auto<T>& operator= (const ossl_auto<T>&) = delete;
    
    // move constructor and move assignment
    ossl_auto(ossl_auto<T>&& other)
    {
        move(other);
    }
    ossl_auto<T>& operator=(ossl_auto<T>&& other)
    {
        move(other);
        return *this;
    }

    ossl_auto(T* _ptr)
    {
        ptr = _ptr;
    }
    
    ossl_auto<T>& operator=(T* _ptr)
    {
        if (isInitialized())
            throw_java_ex(EX_RUNTIME_CRYPTO, "reassigning, loosing pointer without freeing");
        ptr = _ptr;
        return *this;
    }
    

    static ossl_auto from(T* p)
    {
        ossl_auto<T> tmp;
        tmp.ptr = p;
        return tmp;
    }
    ~ossl_auto()
    {
        clear();
    }

    bool isInitialized()
    {
        return (ptr != NULL);
    }
    bool set(T* p)
    {
        clear();
        ptr = p;
        return (ptr != NULL);
    }
    T* take()
    {
        T* tmp = ptr;
        ptr = NULL;
        return tmp;
    }
    void releaseOwnership()
    {
        ptr = NULL;
    }
    void clear()
    {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Reached generic clear for auto destruct");
    }

    T* get()
    {
        return ptr;
    }
    T** getAddressOfPtr()
    {
        return &ptr;
    }

    // operator overloads that make this behave like a raw pointer
    T* operator->()
    {
        return *this;
    }
    operator T* ()
    {
        if (ptr == NULL)
            abort();

        return ptr;
    }
    T** operator&()
    {
        return &ptr;
    }

    operator jbyte* ()
    {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Convert a pointer to jbyte* when it is not such a pointer");
    }

    operator jbyte* () const
    {
        throw_java_ex(EX_RUNTIME_CRYPTO, "Convert a pointer to jbyte* const when it is not such a pointer");
    }
};


template<>
void ossl_auto<EVP_CIPHER>::clear();

template<>
void ossl_auto<EVP_CIPHER_CTX>::clear();

template<>
void ossl_auto<EVP_PKEY>::clear();

template<>
void ossl_auto<EVP_PKEY_CTX>::clear();

template<>
void ossl_auto<PKCS8_PRIV_KEY_INFO>::clear();

template<>
void ossl_auto<EVP_MD_CTX>::clear();

template<>
void ossl_auto<EVP_MAC_CTX>::clear();

template<>
void ossl_auto<EVP_MAC>::clear();

template<>
void ossl_auto<EVP_KDF>::clear();

template<>
void ossl_auto<EVP_KDF_CTX>::clear();

template<>
void ossl_auto<OSSL_ENCODER_CTX>::clear();

template<>
void ossl_auto<OSSL_DECODER_CTX>::clear();

template<>
void ossl_auto<OSSL_PARAM>::clear();

template<>
void ossl_auto<OSSL_PARAM_BLD>::clear();

template<>
void ossl_auto<ASN1_OBJECT>::clear();

template<>
void ossl_auto<unsigned char>::clear();


template<>
ossl_auto<unsigned char>::operator jbyte* ();

template<>
ossl_auto<unsigned char>::operator jbyte* () const;

#endif