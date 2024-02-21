// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef BUFFER_H
#define BUFFER_H

#include "env.h"
#include <vector>

namespace AmazonCorrettoCryptoProvider {

jbyteArray vecToArray(raii_env& env, const std::vector<uint8_t, SecureAlloc<uint8_t> >& vec);

/**
 * This class represents some kind of java buffer - whether it's a slice of a
 * java array or a direct byte buffer.
 *
 * To gain access to the data in the buffer, use the jni_borrow class.
 *
 * The java_buffer class itself only contains metadata, so it can be copied using
 * the usual copy constructors. To construct from a Java object, use the static from_*
 * methods - note that these make JNI calls, so they cannot be used when a borrow is
 * active.
 */

/**
 * LiYK: This class defines two ways to create such a java_buffer object, namely from_array and from_direct
 * There isn't a decisive reason why there are only two ways. This just artificially dictates the creator of
 * an object of this class to have either one of the two, because array and direct buffer are the most common
 * ways to hold consecutive data in Java.
*/

/**
 * LiYK: The idea is to note down only meta data in java_buffer, if I want to access the data, I need to create a borrow.
 * The most important thing needed to be done when creating a borrow is to identify the pointer that points to the start
 * of the native array. If the java_buffer object is created out of a Java array type object, I only note down the jbyteArray
 * variable (remember that when Java passes a byte[] to JNI, JNI gets a jbyteArray which is essentially a pointer to an object).
 * When creating a borrow out of such java_buffer, I need to use GetPrimitiveArrayCritical to get the pointer to the native array.
 * But when creating a java_buffer out of a Java direct buffer, I guess because of some uniqueness of direct buffer, we just
 * call GetDirectBufferAddress and get the pointer to the native array already. The m_pBuffer in jni_borrow is supposed to be
 * the pointer to the native array. Note that when the original source is a direct buffer, m_pBuffer is simply assigned with
 * m_direct_buffer from java_buffer.
 * To summarize:
 *     when original source is a Java byte array, I note down jbyteArray when creating java_buffer, and get the real
 *     pointer later when I create jni_borrow. 
 * 
 *     when original source is a Java direct buffer, I already get the real pointer when creating java_buffer (because it's easy to do so?).
 *     the job becomes easier when later creating jni_borrow
 * 
*/

/**
* LiYK: java_buffer actually has get_bytes and put_bytes member functions. We usually see java_buffer and jni_borrow used in tandem,
* but that is not absolutely necessary. I can just use java_buffer and get_bytes and put_bytes without creating jni_borrow.
* When I use get_bytes / put_butes if there is no other jni_borrow on the env pointer and its underlying memory is from java array,
* get_bytes / put_bytes won't use pinning (i.e. Get/ReleasePrivimiteArrayCritical)
*/

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
    // LiYK: If I have a valid array or buffer, "!()" evaluates to false, "!!()" evaluates to true.

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

    /**
     * Verifies that the range of bytes between 'offset' and 'offset + len' is
     * within the bounds of this buffer. If not, an exception is thrown.
     */
    void check_bounds(size_t offset, size_t len) const
    {
        if (unlikely(!*this)) {
            throw java_ex(EX_NPE, "Null buffer");
        }

        if (unlikely(!::AmazonCorrettoCryptoProvider::check_bounds(this->len(), offset, len))) {
            throw java_ex(EX_ARRAYOOB, "Attempted to access outside the bounds of the buffer");
        }
    }

    /**
     * Copies 'len' bytes from the buffer, starting at 'offset') to 'dest'.
     *
     * If something goes wrong (e.g. bounds check on the buffer), a java_ex
     * will be thrown
     */
    void get_bytes(raii_env& env, uint8_t* dest, size_t offset, size_t len) const;

    /**
     * Copies 'len' bytes from 'src' to the buffer, starting at 'offset' within this java_buffer.
     *
     * If something goes wrong (e.g. bounds check on the buffer), a java_ex
     * will be thrown
     */
    void put_bytes(raii_env& env, const uint8_t* src, size_t offset, size_t len);

    /**
     * Copies this java buffer to a C++ vector.
     */
    std::vector<uint8_t, SecureAlloc<uint8_t> > to_vector(raii_env& env) const;

    /**
     * Constructs a java buffer representing the entirety of a direct byte buffer.
     *
     * If the passed object is not a direct buffer, an appropriate java_ex will be thrown.
     *
     * It is the caller's responsibility to ensure that the direct_buffer object remains referenced
     * (in Java) as long as the java_buffer exists.
     */
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

    /**
     * Constructs a java buffer representing a slice of an array.
     *
     * If the passed pointer is not a byte array, or the offset and length point outside the
     * array, then an appropriate java_ex will be thrown.
     *
     * This class does not manage the lifetime of the array reference - the caller must ensure that
     * usage of the java_buffer does not outlive the underlying array reference, and must ensure that
     * if the array reference is a local reference, that the java_buffer does not cross threads.
     */
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

    /**
     * Constructs a java_buffer from a java byte array, starting at the specified offset and continuing
     * until the end of the array.
     *
     * Throws an appropriate java_ex if the passed pointer is not an array.
     *
     * This class does not manage the lifetime of the array reference - the caller must ensure that
     * usage of the java_buffer does not outlive the underlying array reference, and must ensure that
     * if the array reference is a local reference, that the java_buffer does not cross threads.
     */
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

    /**
     * Returns the length, in bytes, of the data represented by this java_buffer.
     */
    size_t len() const { return m_length; }

    /**
     * Returns the underlying java array, or a nullptr if this is backed by a direct byte buffer
     * or is null.
     */
    jbyteArray array() const { return m_array; }
};

/**
 * A jni_borrow represents a slice of memory "borrowed" from the JVM.
 * This can either be a direct byte buffer, or an array accessed by an active
 * GetPrimitiveArrayCritical buffer lock.
 */
class jni_borrow {
private:

    
    // LiYK: A jni_borrow is associated to either a java array or a java direct buffer. In case of java array
    // accessing the data has to be enclosed by Get/ReleasePrimitiveArrayCritical. Such requirement makes code
    // around jni_borrow feel like the handling of a lock where I need to lock and release.
    // In order to not forget to call Release, I link all the jni_borrow objects in a list and the list behaves
    // like a stack, i.e. a jni_borrow is pushed onto the stack when it's Get...Critical, and the last Get
    // must the first Release. Then I associate such list(stack) with an raii_env, because the Get/Release...Critical
    // calls are env member functions. All these efforts just ensure the Get and Release calls for jni_borrows are
    // paired up.

    // The borrow that was opened before us, if any
    jni_borrow* m_prior_borrow;
    // The borrow that was opened after us, if any
    jni_borrow* m_next_borrow;
    // The JNI context we were spawned from
    raii_env* m_context;
    // Debug information on where this borrow was opened
    const char* m_trace;
    // Data length
    size_t m_length;
    // Java array, if any
    jbyteArray m_array;
    // Pointer to the original java buffer
    void* m_pBuffer;
    // True if this represents a locked array, false for a direct buffer reference
    bool m_is_locked;
    // Pointer to the data slice within the buffer
    void* m_pData;

    void bad_release() COLD NORETURN;

    friend class raii_env;

    void clear() ALWAYS_INLINE
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
    // Do not allow implicit copy constructors
    jni_borrow(const jni_borrow&) = delete;
    jni_borrow& operator=(const jni_borrow&) = delete;

    // Move semantics
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
    // On a pre-C++11 compiler, we do an awful hack and mutate the passed-in
    // (const) reference.
    jni_borrow& operator=(const jni_borrow& other)
    {
        move(const_cast<jni_borrow&>(other)); // LiYK: const_cast converts a const reference to a non-const reference, "cast" means "throw away"
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
            // Not initialized
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

    operator uint8_t*() { return data(); }  // LiYK: conversion operator that converts an object to a pointer to uint8_t
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

    if (env.is_locked() || m_direct_buffer) {  // if is_locked, other java_buffer (from java array) is being accessed by jni_borrow, native code is in a critical section, must not call any other JNI functions
        jni_borrow borrow(env, *this, "put_bytes");
        memcpy(borrow + offset, src, len);
    } else {
        env->SetByteArrayRegion(m_array, this->m_offset + offset, len, (const jbyte*)src);
        env.rethrow_java_exception();
    }
}

/**
 * A bounce buffer is a buffer that is _copied_ from a Java array or byte buffer.
 * Upon destruction, it is copied back. For small amounts of data (where the size is known at compile-time)
 * it can be more efficient and more flexible than using jni_borrow (which usually enters a critical region).
 *
 * T must have a trivial default constructor and be trivially copyable.
 */

/**
* LiYK: This one is almost the same as jni_borrow.
* Differences:
* (1). When dealing with java array, bounce_buffer doesn't use pinning (i.e. doesn't use Get/ReleasePrimitiveArrayCritical)
* (2). bounce_buffer doesn't deal with a consecutive block of data, rather, it deals with a C++ object whose content is stored in a block of memory.
*      This bounce_buffer basically restores the object from the opaque memory and later writes to opaque memory again.
*      This is basically the simplest serialization/deserialization operation.
*      This is why the template parameter T must be travially copyable, because the deserialization process is just memory copy
* (3). When jni_borrow is created, the underlying memory is not read yet, only pointers are saved.
*      When bounce_buffer is created, the memory is immediately read and deserialized into object of type T, when bounce_buffer is destructed,
*      object of type T is written back to the underlying memory.
*/

template <typename T> class bounce_buffer {
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
    /**
     * The default constructor creates an unusable bounce buffer. This is here
     * just to allow code that looks like C++11 code to compile (with weird
     * not-quite-move semantics) on older compilers.
     */
    bounce_buffer()
    {
        m_pEnv = nullptr;
        m_valid = false;
    }

#ifdef HAVE_CPP11
    // Remove default copy/assign operators
    bounce_buffer(const bounce_buffer&) DELETE_IMPLICIT;
    bounce_buffer& operator=(const bounce_buffer&) DELETE_IMPLICIT;

    // Move semantics
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
    // Emulate move semantics on pre-C++11 compilers
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

    static bounce_buffer from_array(raii_env& env, jbyteArray array) ALWAYS_INLINE
    {
        return bounce_buffer(env, java_buffer::from_array(env, array));
    }

    // We force inlining because, in many cases, the buffer.array() && !env.is_locked()
    // clause can be determined using compile-time information, allowing for this test to
    // be optimized out.
    bounce_buffer(raii_env& env, java_buffer buffer) ALWAYS_INLINE
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

    ~bounce_buffer() ALWAYS_INLINE { release(); }

    void release() ALWAYS_INLINE
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



// Please follow the guidelines outlined in {Get,Release}PrimitiveArrayCritical when using this class:
// https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#GetPrimitiveArrayCritical_ReleasePrimitiveArrayCritical

// LiYK: this is no different than creating java_buffer and then creating jni_borrow out of java_buffer,
// why using a separate class? Or what is the difference?

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
