#include "jni_md.h"

#include "env.h"
#include "util.h"
#include "auto_free.h"

#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/asn1.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>

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
void ossl_auto<PKCS8_PRIV_KEY_INFO>::clear()
{
    if (ptr != NULL)
        PKCS8_PRIV_KEY_INFO_free(ptr);
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
void ossl_auto<EVP_MD>::clear()
{
    if (ptr != NULL)
        EVP_MD_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_MAC_CTX>::clear()
{
    if (ptr != NULL)
        EVP_MAC_CTX_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_MAC>::clear()
{
    if (ptr != NULL)
        EVP_MAC_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_KDF>::clear()
{
    if (ptr != NULL)
        EVP_KDF_free(ptr);
    ptr = NULL;
}

template<>
void ossl_auto<EVP_KDF_CTX>::clear()
{
    if (ptr != NULL)
        EVP_KDF_CTX_free(ptr);
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