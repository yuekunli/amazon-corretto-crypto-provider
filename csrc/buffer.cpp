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
