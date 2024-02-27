// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef BUFFER_H
#define BUFFER_H

#include "env.h"
#include "util.h"
#include <vector>

namespace AmazonCorrettoCryptoProvider {

jbyteArray vecToArray(raii_env& env, const std::vector<uint8_t, SecureAlloc<uint8_t> >& vec);

class java_buffer {
private:
    jbyteArray m_array;
    void* m_direct_buffer;
    size_t m_offset;
    size_t m_length;

    friend class jni_borrow;

public:
    java_buffer()
        : m_array(nullptr)
        , m_direct_buffer(nullptr)
        , m_offset(0)
        , m_length(0)
    {
    }

    bool operator!() const { return !(m_array || m_direct_buffer); }

    java_buffer subrange(size_t offset, size_t len) const
    {
        check_bounds(offset, len);

        java_buffer newbuf = *this;
        newbuf.m_length = len;

        if (newbuf.m_array) {
            newbuf.m_offset += offset;
        } else {
            newbuf.m_direct_buffer = (uint8_t*)m_direct_buffer + offset;
        }

        return newbuf;
    }

    java_buffer subrange(size_t offset) const
    {
        if (m_length >= offset)
            return subrange(offset, m_length - offset);
        else
            return subrange(offset, 0);
    }

    void check_bounds(size_t offset, size_t len) const
    {
        if (unlikely(!*this)) {
            throw java_ex(EX_NPE, "Null buffer");
        }

        if (unlikely(!::AmazonCorrettoCryptoProvider::check_bounds(this->len(), offset, len))) {
            throw java_ex(EX_ARRAYOOB, "Attempted to access outside the bounds of the buffer");
        }
    }

    void get_bytes(raii_env& env, uint8_t* dest, size_t offset, size_t len) const;

    void put_bytes(raii_env& env, const uint8_t* src, size_t offset, size_t len);

    std::vector<uint8_t, SecureAlloc<uint8_t> > to_vector(raii_env& env) const;

    static java_buffer from_direct(raii_env& context, jobject direct_buffer)
    {
        if (unlikely(!direct_buffer)) {
            throw java_ex(EX_NPE, "Null direct buffer passed");
        }

        void* p_direct_buffer = context->GetDirectBufferAddress(direct_buffer);

        if (unlikely(!p_direct_buffer)) {
            throw java_ex(EX_ILLEGAL_ARGUMENT, "Not a direct buffer");
        }

        jlong buffer_cap = context->GetDirectBufferCapacity(direct_buffer);
        if (unlikely((jint)buffer_cap != buffer_cap || buffer_cap < 0)) {
            throw java_ex(EX_ILLEGAL_ARGUMENT, "Unsupported buffer length");
        }

        java_buffer buf;
        buf.m_direct_buffer = p_direct_buffer;
        buf.m_offset = 0;
        buf.m_length = buffer_cap;

        return buf;
    }

    static java_buffer from_array(raii_env& context, jbyteArray array, jint offset, jint length)
    {
        if (unlikely(!array)) {
            throw java_ex(EX_NPE, "Null array passed");
        }

        java_buffer buf;

        buf.m_array = array;
        buf.m_direct_buffer = nullptr;
        buf.m_offset = offset;
        buf.m_length = length;

        jint true_length = context->GetArrayLength(array);

        if (unlikely(true_length) < 0) {
            throw java_ex("java/lang/AssertionError", "Impossible: Negative array length");
        }

        if (unlikely(!::AmazonCorrettoCryptoProvider::check_bounds(true_length, offset, length))) {
            throw java_ex("java/lang/ArrayIndexOutOfBoundsException", "Array offset is outside of array bounds");
        }

        return buf;
    }

    static java_buffer from_array(raii_env& context, jbyteArray array, size_t offset = 0)
    {
        if (unlikely(!array)) {
            throw java_ex(EX_NPE, "Null array passed");
        }

        if (unlikely(offset < 0)) {
            throw java_ex(EX_ARRAYOOB, "Negative array offset passed");
        }

        java_buffer buf;

        buf.m_array = array;
        buf.m_direct_buffer = nullptr;
        buf.m_offset = offset;
        buf.m_length = context->GetArrayLength(array);

        if (unlikely(buf.m_length) < 0) {
            throw java_ex("java/lang/AssertionError", "Impossible: Negative array length");
        }

        if (unlikely(buf.m_length < offset)) {
            throw java_ex(EX_ARRAYOOB, "Offset starts past end of array");
        }

        buf.m_length -= offset;

        return buf;
    }

    size_t len() const { return m_length; }

    jbyteArray array() const { return m_array; }
};


class jni_borrow {
private:

    jni_borrow* m_prior_borrow;
    
    jni_borrow* m_next_borrow;
    
    raii_env* m_context;
    
    const char* m_trace;
    
    size_t m_length;
    
    jbyteArray m_array;
    
    void* m_pBuffer;
    
    bool m_is_locked;
    
    void* m_pData;

    NORETURN1 void bad_release() COLD NORETURN2;

    friend class raii_env;

    FORCE_INLINE1 void clear() FORCE_INLINE2
    {
        m_next_borrow = nullptr;
        m_prior_borrow = nullptr;
        m_context = nullptr;
        m_trace = nullptr;
        m_length = 0;
        m_array = nullptr;
        m_pBuffer = nullptr;
        m_is_locked = false;
        m_pData = nullptr;
    }

    void move(jni_borrow& other)
    {
        release();

        m_next_borrow = other.m_next_borrow;
        m_prior_borrow = other.m_prior_borrow;
        if (m_next_borrow) {
            m_next_borrow->m_prior_borrow = this;
        }
        if (m_prior_borrow) {
            m_prior_borrow->m_next_borrow = this;
        }
        if (m_context->m_last_buffer_lock == &other) {
            m_context->m_last_buffer_lock = this;
        }

        m_context = other.m_context;
        m_trace = other.m_trace;
        m_length = other.m_length;
        m_array = other.m_array;
        m_pBuffer = other.m_pBuffer;
        m_is_locked = other.m_is_locked;
        m_pData = other.m_pData;

        other.clear();
    }

public:
    jni_borrow() { clear(); }

#ifdef HAVE_CPP11

    jni_borrow(const jni_borrow&) = delete;
    jni_borrow& operator=(const jni_borrow&) = delete;

    jni_borrow& operator=(jni_borrow&& other)
    {
        move(other);
        return *this;
    }
    jni_borrow(jni_borrow&& other)
    {
        clear();
        move(other);
    }
#else
    jni_borrow& operator=(const jni_borrow& other)
    {
        move(const_cast<jni_borrow&>(other));
        return *this;
    }

    jni_borrow(const jni_borrow& other)
    {
        clear();
        *this = other;
    }
#endif

    jni_borrow(raii_env& context, java_buffer buffer, const char* trace)
    {
        assert(!!buffer);
        clear();

        m_prior_borrow = context.m_last_buffer_lock;
        m_context = &context;
        m_trace = trace;
        m_length = buffer.len();

        if (buffer.m_direct_buffer) {
            m_array = nullptr;
            m_is_locked = false;
            m_pBuffer = buffer.m_direct_buffer;
        } else {
            void* ptr = context.m_env->GetPrimitiveArrayCritical(buffer.m_array, NULL);
            if (unlikely(!ptr)) {
                throw java_ex(EX_ERROR, "Failed to lock byte array");
            }

            m_array = buffer.m_array;
            m_pBuffer = ptr;
            m_is_locked = true;
        }
        m_pData = (uint8_t*)m_pBuffer + buffer.m_offset;
        context.m_last_buffer_lock = this;
        if (m_prior_borrow) {
            m_prior_borrow->m_next_borrow = this;
        }
    }

    virtual ~jni_borrow() { release(); }

    void release()
    {
        if (!m_context) {
            return;
        }

        if (unlikely(m_context->m_last_buffer_lock != this)) { 
            bad_release();
        }
        assert(!m_next_borrow);

        if (m_is_locked) {
            m_context->m_env->ReleasePrimitiveArrayCritical(m_array, m_pBuffer, 0);
        }
        m_context->m_last_buffer_lock = m_prior_borrow;
        if (m_prior_borrow)
            m_prior_borrow->m_next_borrow = nullptr;

        clear();
    }

    const uint8_t* data() const { return const_cast<jni_borrow*>(this)->data(); }

    uint8_t* data() { return (uint8_t*)m_pData; }

    operator uint8_t*() { return data(); }

    operator const uint8_t*() const { return data(); }

    uint8_t* check_range(size_t off, size_t len)
    {
        if (unlikely(!check_bounds(this->len(), off, len))) {
            throw_java_ex(EX_ARRAYOOB, "Attempted access outside array bounds");
        }

        return data() + off;
    }

    const uint8_t* check_range(size_t off, size_t len) const
    {
        return const_cast<jni_borrow*>(this)->check_range(off, len);
    }

    size_t len() const { return m_length; }

    void zeroize() { secureZero(data(), len()); }
};

inline void java_buffer::get_bytes(raii_env& env, uint8_t* dest, size_t offset, size_t len) const
{
    if (len == 0) {
        return;
    }
    check_bounds(offset, len);

    if (env.is_locked() || m_direct_buffer) {
        jni_borrow borrow(env, *this, "get_bytes");
        memcpy(dest, borrow + offset, len);
    } else {
        env->GetByteArrayRegion(m_array, this->m_offset + offset, len, (jbyte*)dest);
        env.rethrow_java_exception();
    }
}

inline void java_buffer::put_bytes(raii_env& env, const uint8_t* src, size_t offset, size_t len)
{
    if (len == 0) {
        return;
    }
    check_bounds(offset, len);

    if (env.is_locked() || m_direct_buffer) {
        jni_borrow borrow(env, *this, "put_bytes");
        memcpy(borrow + offset, src, len);
    } else {
        env->SetByteArrayRegion(m_array, this->m_offset + offset, len, (const jbyte*)src);
        env.rethrow_java_exception();
    }
}


template <typename T> 
class bounce_buffer {

private:

#ifdef HAVE_IS_TRIVIALLY_COPYABLE
    static_assert(std::is_trivially_copyable<T>::value, "Type must be trivially copyable");
#endif

#ifdef HAVE_IS_TRIVIALLY_DESTRUCTABLE
    static_assert(std::is_trivially_destructable<T>::value, "Type must be trivially destructable");
#endif

    T m_storage;
    java_buffer m_buffer;
    raii_env* m_pEnv;
    bool m_valid;

    void move(bounce_buffer<T>& other)
    {
        release();
        if (other.m_valid) {
            memcpy(&m_storage, &other.m_storage, sizeof(m_storage));
            m_buffer = other.m_buffer;
            m_pEnv = other.m_pEnv;
            m_valid = true;

            other.m_valid = false;
        }
    }

public:

    bounce_buffer()
    {
        m_pEnv = nullptr;
        m_valid = false;
    }

#ifdef HAVE_CPP11

    bounce_buffer(const bounce_buffer&) DELETE_IMPLICIT;
    bounce_buffer& operator=(const bounce_buffer&) DELETE_IMPLICIT;

    bounce_buffer(bounce_buffer&& movesrc)
    {
        m_pEnv = nullptr;
        m_valid = false;

        move(movesrc);
    }

    bounce_buffer& operator=(bounce_buffer&& movesrc)
    {
        move(movesrc);

        return *this;
    }
#else
    bounce_buffer& operator=(const bounce_buffer& other)
    {
        move(const_cast<bounce_buffer&>(other));
        return *this;
    }

    bounce_buffer(const bounce_buffer& other)
    {
        m_pEnv = nullptr;
        m_valid = false;

        *this = other;
    }
#endif

    FORCE_INLINE1 static bounce_buffer from_array(raii_env& env, jbyteArray array) FORCE_INLINE2
    {
        return bounce_buffer(env, java_buffer::from_array(env, array));
    }

    FORCE_INLINE1 bounce_buffer(raii_env& env, java_buffer buffer) FORCE_INLINE2
    {
        m_buffer = buffer;

        if (unlikely(sizeof(T) != m_buffer.len())) {
            throw new java_ex(EX_ILLEGAL_ARGUMENT, "Incorrect length for buffer");
        }

        if (buffer.array() && !env.is_locked()) {
            env->GetByteArrayRegion(buffer.array(), 0, sizeof(m_storage), reinterpret_cast<jbyte*>(&m_storage));
            env.rethrow_java_exception();
        } else {
            jni_borrow borrow(env, m_buffer, "bounce buffer");
            memcpy(&m_storage, borrow.data(), sizeof(m_storage));
        }

        m_pEnv = &env;
        m_valid = true;
    }

    FORCE_INLINE1 ~bounce_buffer() FORCE_INLINE2 { release(); }

    FORCE_INLINE1 void release() FORCE_INLINE2
    {
        if (!m_valid)
            return;

        raii_env& env = *m_pEnv;

        if (m_buffer.array() && !env.is_locked()) {
            env->SetByteArrayRegion(m_buffer.array(), 0, sizeof(m_storage), reinterpret_cast<jbyte*>(&m_storage));
            env.rethrow_java_exception();
        } else {
            jni_borrow borrow(env, m_buffer, "bounce buffer");
            memcpy(borrow.data(), &m_storage, sizeof(m_storage));
        }

        secureZero(&m_storage, sizeof(m_storage));
    }

    T* ptr()
    {
        assert(m_valid);
        return &m_storage;
    }

    const T* ptr() const
    {
        assert(m_valid);
        return &m_storage;
    }

    operator T*() { return ptr(); }
    operator const T*() const { return ptr(); }

    T* operator->() { return ptr(); }
    const T* operator->() const { return ptr(); }

    void zeroize() { secureZero(&m_storage, sizeof(m_storage)); }
};


class JByteArrayCritical {
public:
    JByteArrayCritical(JNIEnv* env, jbyteArray jarray);
    ~JByteArrayCritical();
    unsigned char* get();

private:
    void* ptr_;
    JNIEnv* env_;
    jbyteArray jarray_;
};

}
#endif
