// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "buffer.h"

namespace AmazonCorrettoCryptoProvider {

void jni_borrow::bad_release() {
    std::cerr << "Released borrows in the wrong order; releasing " << m_trace << " but borrow stack is:" << std::endl;
    m_context->buffer_lock_trace();
    abort();
}

std::vector<uint8_t, SecureAlloc<uint8_t> > java_buffer::to_vector(raii_env &env) const {
    std::vector<uint8_t, SecureAlloc<uint8_t> > vec(len());

    get_bytes(env, &vec[0], 0, vec.size());

    return vec;
}

jbyteArray vecToArray(raii_env &env, const std::vector<uint8_t, SecureAlloc<uint8_t> > &vec) {
    jbyteArray array = env->NewByteArray(vec.size());
    if (!array) {
        throw_java_ex(EX_OOM, "Failed to allocate memory for returned byte array");
    }

    env->SetByteArrayRegion(array, 0, vec.size(), reinterpret_cast<const jbyte *>(&vec[0]));

    // If something went wrong above, rethrow that exception as a C++ exception now
    env.rethrow_java_exception();

    return array;
}

}
