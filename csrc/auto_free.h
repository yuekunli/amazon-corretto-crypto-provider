// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AUTO_FREE_H
#define AUTO_FREE_H

#include "env.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
//#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

// These macros allow us to easily defined stack managed versions of various Openssl structures.
// Some objects will require custom implementations (such as unsigned char* and BN).
// In order for this to work the following methods must be defined:
// FOO_free(FOO*)

#define CLASSNAME(name) CONCAT2(name, _auto)
#define PTR_NAME(name)  CONCAT2(p, name)
#ifdef HAVE_CPP11
#define AUTO_CONSTRUCTORS(name)                                                                                        \
    /* Do not allow implicit copy constructors */                                                                      \
    CLASSNAME(name)                                                                                                    \
    (const CLASSNAME(name)&) = delete;                                                                                 \
    CLASSNAME(name)& operator=(const CLASSNAME(name)&) = delete;                                                       \
    /* Move semantics */                                                                                               \
    CLASSNAME(name)& operator=(CLASSNAME(name) && other)                                                               \
    {                                                                                                                  \
        move(other);                                                                                                   \
        return *this;                                                                                                  \
    }                                                                                                                  \
    CLASSNAME(name)                                                                                                    \
    (CLASSNAME(name) && other) { move(other); }
#else
#define AUTO_CONSTRUCTORS(name)                                                                                        \
    /* On a pre-C++11 compiler, we do an awful hack and mutate the passed-in (const) reference. */                     \
    CLASSNAME(name)& operator=(const CLASSNAME(name) & other)                                                          \
    {                                                                                                                  \
        move(const_cast<CLASSNAME(name)&>(other));                                                                     \
        return *this;                                                                                                  \
    }                                                                                                                  \
    CLASSNAME(name)                                                                                                    \
    (const CLASSNAME(name) & other)                                                                                    \
    {                                                                                                                  \
        clear();                                                                                                       \
        *this = other;                                                                                                 \
    }
#endif

#define OPENSSL_auto(name)                                                                                             \
    class CLASSNAME(name) {                                                                                            \
    private:                                                                                                           \
        name* PTR_NAME(name);                                                                                          \
        void move(CLASSNAME(name) & other) { set(other.take()); }                                                      \
                                                                                                                       \
    public:                                                                                                            \
        AUTO_CONSTRUCTORS(name)                                                                                        \
        CLASSNAME(name)() { PTR_NAME(name) = NULL; }                                                                   \
        static CLASSNAME(name) from(name* ptr)                                                                         \
        {                                                                                                              \
            CLASSNAME(name) tmp;                                                                                       \
            tmp.PTR_NAME(name) = ptr;                                                                                  \
            return tmp;                                                                                                \
        }                                                                                                              \
        ~CLASSNAME(name)() { clear(); }                                                                                \
        bool isInitialized() { return !!PTR_NAME(name); }                                                              \
        bool set(name* ptr)                                                                                            \
        {                                                                                                              \
            clear();                                                                                                   \
            PTR_NAME(name) = ptr;                                                                                      \
            return !!ptr;                                                                                              \
        }                                                                                                              \
        name* take()                                                                                                   \
        {                                                                                                              \
            name* tmpPtr = PTR_NAME(name);                                                                             \
            PTR_NAME(name) = NULL;                                                                                     \
            return tmpPtr;                                                                                             \
        }                                                                                                              \
        void releaseOwnership() { PTR_NAME(name) = NULL; }                                                             \
        void clear()                                                                                                   \
        {                                                                                                              \
            CONCAT2(name, _free)(PTR_NAME(name));                                                                      \
            PTR_NAME(name) = NULL;                                                                                     \
        }                                                                                                              \
        name* operator->() { return *this; }                                                                           \
        operator name*()                                                                                               \
        {                                                                                                              \
            if (!PTR_NAME(name)) {                                                                                     \
                abort();                                                                                               \
            }                                                                                                          \
            return PTR_NAME(name);                                                                                     \
        }                                                                                                              \
        name* get() { return PTR_NAME(name); }                                                                         \
        name** getAddressOfPtr() { return &PTR_NAME(name); }                                                           \
    }

//OPENSSL_auto(RSA);
OPENSSL_auto(PKCS8_PRIV_KEY_INFO);
OPENSSL_auto(EC_GROUP);
OPENSSL_auto(EC_POINT);
OPENSSL_auto(EC_KEY);
OPENSSL_auto(BN_CTX);
OPENSSL_auto(EVP_MD_CTX);
OPENSSL_auto(EVP_PKEY);
OPENSSL_auto(EVP_PKEY_CTX);



class RSA_auto
{
private:
    RSA* pRSA;
    void move(RSA_auto& other)
    {
        set(other.take());
    }

public:
    RSA_auto(const RSA_auto&) = delete;
    RSA_auto& operator=(const RSA_auto&) = delete;
    RSA_auto& operator=(RSA_auto&& other)
    {
        move(other);
        return *this;
    }
    RSA_auto(RSA_auto&& other)
    {
        move(other);
    }
    RSA_auto()
    {
        pRSA = 0;
    }
    static RSA_auto from(RSA* ptr)
    {
        RSA_auto tmp;
        tmp.pRSA = ptr;
        return tmp;
    }
    ~RSA_auto()
    {
        clear();
    }
    bool isInitialized()
    {
        return !!pRSA;
    }
    bool set(RSA* ptr)
    {
        clear();
        pRSA = ptr;
        return !!ptr;
    }
    RSA* take()
    {
        RSA* tmpPtr = pRSA;
        pRSA = 0;
        return tmpPtr;
    }
    void releaseOwnership()
    {
        pRSA = NULL;
    }
    void clear()
    {
        RSA_free(pRSA);
        pRSA = NULL;
    }
    RSA* operator->()
    {
        return *this;
    }
    operator RSA* ()
    {
        if (!pRSA)
        {
            abort();
        }
        return pRSA;
    }
    RSA* get()
    {
        return pRSA;
    }
    RSA** getAddressOfPtr()
    {
        return &pRSA;
    }
};


template<typename T>
class ossl_auto
{
private:
    T* ptr;
    void move(ossl_auto<T>& other);
public:
    ossl_auto(const ossl_auto<T>&) = delete;
    ossl_auto<T>& operator= (const ossl_auto<T>&) = delete;
    ossl_auto<T>& operator=(ossl_auto<T>&& other)
    {
        move(other);
        return *this;
    }
    ossl_auto(ossl_auto<T>&& other)
    {
        move(other);
    }
    ossl_auto() :ptr(NULL) {}

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
    T* get()
    {
        return ptr;
    }
    T** getAddressOfPtr()
    {
        return &ptr;
    }

};


template<>
void ossl_auto<EVP_PKEY>::clear()
{
    EVP_PKEY_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_PKEY_CTX>::clear()
{
    EVP_PKEY_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_MD_CTX>::clear()
{
    EVP_MD_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_ENCODER_CTX>::clear()
{
    OSSL_ENCODER_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_DECODER_CTX>::clear()
{
    OSSL_DECODER_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_PARAM>::clear()
{
    OSSL_PARAM_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<OSSL_PARAM_BLD>::clear()
{
    OSSL_PARAM_BLD_free(ptr);
    ptr = NULL;
}


// LiYK: this class doesn't have a constructor that specifies a size so that, when instantiating, constructor allocates memory.
// This is because this class is usually used when the address of the pointer is passed to a function where memory is allocated,
// and the pointer is made to point at that memory.
class OPENSSL_buffer_auto {
private:
    OPENSSL_buffer_auto(const OPENSSL_buffer_auto&) DELETE_IMPLICIT;
    OPENSSL_buffer_auto& operator=(const OPENSSL_buffer_auto&) DELETE_IMPLICIT;

public:
    unsigned char* buf;

    explicit OPENSSL_buffer_auto()
        : buf(NULL)
    {
    }

    virtual ~OPENSSL_buffer_auto() { OPENSSL_free(buf); }

    operator unsigned char*() { return buf; }

    operator unsigned char*() const { return buf; }

    unsigned char** operator&() { return &buf; }

    operator jbyte*() { return reinterpret_cast<jbyte*>(buf); }

    operator jbyte*() const { return reinterpret_cast<jbyte*>(buf); }
};

#undef AUTO_CONSTRUCTORS
#undef CLASSNAME
#undef OPENSSL_auto
#endif
