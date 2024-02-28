// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef BN_H
#define BN_H

#include "buffer.h"
#include "compiler.h"
#include "env.h"
#include <openssl/bn.h>

namespace AmazonCorrettoCryptoProvider {

void jarr2bn(raii_env& env, jbyteArray array, BIGNUM* bn);
void jarr2bn(raii_env& env, const java_buffer& buffer, BIGNUM* bn);
void bn2jarr(raii_env& env, java_buffer& buffer, const BIGNUM* bn);
void bn2jarr(raii_env& env, jbyteArray array, const BIGNUM* bn);
jbyteArray bn2jarr(raii_env& env, const BIGNUM* bn);

class BigNumObj {
private:
    BIGNUM* m_pBN;

    void move(BigNumObj& bn)
    {
        m_pBN = bn.m_pBN;
        bn.m_pBN = NULL;
    }

    void ensure_init() const
    {
        BigNumObj* pThis = const_cast<BigNumObj*>(this);

        if (!pThis->m_pBN) {
            pThis->m_pBN = BN_new();
            if (!pThis->m_pBN) {
                throw_openssl("Failed to allocate a bignum");
            }
        }
    }

public:
    explicit BigNumObj() // when BigNumObj is cast to BIGNUM*, ensure_init is called and that instantiates a BIGNUM object whose value is set to zero.
        : m_pBN(NULL)
    {
    }

    void toJavaArray(raii_env& env, jbyteArray array) const { bn2jarr(env, array, *this); }

    virtual ~BigNumObj()
    {
        if (m_pBN) {
            BN_clear_free(m_pBN);
        }
    }

    BigNumObj clone() const
    {
        BigNumObj rv;

        if (!BN_copy(rv, *this)) {
            throw_openssl("Failed to copy bignum");
        }

        return rv;
    }

    operator BIGNUM*()
    {
        ensure_init();
        return m_pBN;
    }

    operator BIGNUM*() const
    {
        ensure_init();
        return m_pBN;
    }

    BIGNUM** operator&()
    {
        return &m_pBN;
    }

    void releaseOwnership() { m_pBN = NULL; }

    static BigNumObj fromJavaArray(raii_env& env, jbyteArray array)
    {
        BigNumObj result;

        if (array) {
            result.ensure_init();
            jarr2bn(env, array, result.m_pBN);
        }
        return result;
    }

#ifdef HAVE_CPP11
    BigNumObj(const BigNumObj&) = delete;
    BigNumObj& operator=(const BigNumObj&) = delete;

    BigNumObj& operator=(BigNumObj&& bn) noexcept
    {
        move(bn);
        return *this;
    }

    BigNumObj(BigNumObj&& bn) noexcept
        : m_pBN(NULL)
    {
        *this = std::move(bn);
    }
#else
    BigNumObj& operator=(const BigNumObj& other_const)
    {
        BigNumObj& other = const_cast<BigNumObj&>(other_const);

        move(other);

        return *this;
    }

    BigNumObj(const BigNumObj& other)
        : m_pBN(NULL)
    {
        *this = other;
    }

#endif
};

inline static BigNumObj bn_new_zero() { return BigNumObj(); }
inline static bool  BN_null_or_zero(const BIGNUM* bn) { return nullptr == bn || BN_is_zero(bn); }

} // namespace AmazonCorrettoCryptoProvider

#endif
