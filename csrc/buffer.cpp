// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include <openssl/mem.h>
#include <cstdlib>

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

SimpleBuffer::SimpleBuffer(int size)
    : size_(size)
    , buffer_(nullptr)
{
    buffer_ = (uint8_t*)malloc(size);
    if (buffer_ == nullptr) {
        throw java_ex(EX_ERROR, "malloc failed.");
    }
}

SimpleBuffer::~SimpleBuffer()
{
    OPENSSL_cleanse(buffer_, size_);
    free(buffer_);
}

uint8_t* SimpleBuffer::get_buffer() { return buffer_; }

JBinaryBlob::JBinaryBlob(JNIEnv* env, jobject directByteBuffer, jbyteArray array)
    : env_(env)
    , array_(array)
{
    if ((array_ != nullptr) && (directByteBuffer != nullptr)) {
        // One should be null. In the Java layer, we ensure this.
        throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. BOTH directByteBuffer and array cannot be provided.");
    }
    if (array_ != nullptr) {
        ptr_ = (uint8_t*)env->GetPrimitiveArrayCritical(array, nullptr);
        if (ptr_ == nullptr) {
            throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
        }
        return;
    }
    if (directByteBuffer != nullptr) {
        ptr_ = (uint8_t*)env->GetDirectBufferAddress(directByteBuffer);
        if (ptr_ == nullptr) {
            throw java_ex(EX_ERROR, "GetDirectBufferAddress failed.");
        }
        return;
    }
    // In the Java layer, we must ensure that exactly one of them is not null.
    throw java_ex(EX_ERROR, "THIS SHOULD NOT BE REACHABLE. directByteBuffer or array must be provided.");
}

JBinaryBlob::~JBinaryBlob()
{
    if (array_ != nullptr) {
        env_->ReleasePrimitiveArrayCritical(array_, ptr_, 0);
    }
    // For direct ByteBuffers, there is no cleaning up.
}

uint8_t* JBinaryBlob::get() { return ptr_; }

} // end of namespace AmazonCorrettoCryptoProvider
