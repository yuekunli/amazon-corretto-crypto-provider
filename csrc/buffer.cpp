// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"

namespace AmazonCorrettoCryptoProvider {

void jni_borrow::bad_release()
{
    std::cerr << "Released borrows in the wrong order; releasing " << m_trace << " but borrow stack is:" << std::endl;
    m_context->buffer_lock_trace();
    abort();
}

// LiYK: The reason we need the conversion between vector and java_buffer:
// If I really need to copy the content from java_buffer to a local, I don't know the java_buffer length
// in compile time, I can't use a local variable (a C array). I have to allocate memory on the heap.
// And once I allocate on the heap, I must take care of freeing. But if I use vector, its destructor can help free

std::vector<uint8_t, SecureAlloc<uint8_t> > java_buffer::to_vector(raii_env& env) const
{
    std::vector<uint8_t, SecureAlloc<uint8_t> > vec(len());

    get_bytes(env, &vec[0], 0, vec.size());

    return vec;
}

jbyteArray vecToArray(raii_env& env, const std::vector<uint8_t, SecureAlloc<uint8_t> >& vec)
{
    jbyteArray array = env->NewByteArray(vec.size());
    if (!array) {
        throw_java_ex(EX_OOM, "Failed to allocate memory for returned byte array");
    }

    env->SetByteArrayRegion(array, 0, vec.size(), reinterpret_cast<const jbyte*>(&vec[0]));

    // If something went wrong above, rethrow that exception as a C++ exception now
    env.rethrow_java_exception();

    return array;
}

JByteArrayCritical::JByteArrayCritical(JNIEnv* env, jbyteArray jarray)
    : env_(env)
    , jarray_(jarray)
{
    ptr_ = env->GetPrimitiveArrayCritical(jarray, nullptr);
    if (ptr_ == nullptr) {
        throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
    }
}

JByteArrayCritical::~JByteArrayCritical() { env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, 0); }

unsigned char* JByteArrayCritical::get() { return (unsigned char*)ptr_; }

}
