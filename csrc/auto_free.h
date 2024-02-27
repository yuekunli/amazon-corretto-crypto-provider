// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AUTO_FREE_H
#define AUTO_FREE_H

//#include "jni_md.h"

#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/asn1.h>


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
    
    ossl_auto<T>& operator=(const T*)
    {
        if (isInitialized())
            throw_java_ex(EX_RUNTIME_CRYPTO, "reassigning, loosing pointer without freeing");
        ptr = T;
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
void ossl_auto<EVP_CIPHER>::clear()
{
    if (ptr != NULL)
        EVP_CIPHER_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_CIPHER_CTX>::clear()
{
    if (ptr != NULL)
        EVP_CIPHER_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_PKEY>::clear()
{
    if (ptr != NULL)
    EVP_PKEY_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_PKEY_CTX>::clear()
{
    if (ptr != NULL)
    EVP_PKEY_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_MD_CTX>::clear()
{
    if (ptr != NULL)
    EVP_MD_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_ENCODER_CTX>::clear()
{
    if (ptr != NULL)
    OSSL_ENCODER_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_DECODER_CTX>::clear()
{
    if (ptr != NULL)
    OSSL_DECODER_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_PARAM>::clear()
{
    if (ptr != NULL)
    OSSL_PARAM_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_PARAM_BLD>::clear()
{
    if (ptr != NULL)
    OSSL_PARAM_BLD_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<ASN1_OBJECT>::clear()
{
    if (ptr != NULL)
    ASN1_OBJECT_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<unsigned char>::clear()
{
    if (ptr != NULL)
    OPENSSL_free(ptr);
    ptr = NULL;
}


template<>
ossl_auto<unsigned char>::operator jbyte* ()
{
    return reinterpret_cast<jbyte*>(ptr);
}

template<>
ossl_auto<unsigned char>::operator jbyte* () const
{
    return reinterpret_cast<jbyte*>(ptr);
}

#endif