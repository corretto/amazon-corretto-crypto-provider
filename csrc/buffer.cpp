// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "buffer.h"
#include <openssl/mem.h>
#include <cassert>
#include <cstdlib>

namespace AmazonCorrettoCryptoProvider {

#ifndef NDEBUG
// Per-thread count of currently-open JByteArrayCritical regions. Incremented after
// successful GetPrimitiveArrayCritical and decremented in release(). Used by
// commitBack() to assert that no other critical regions are still open on this thread
// when SetByteArrayRegion runs -- which would silently violate JNI's "no other JNI
// calls within a critical region" rule. The count is independent of pin-vs-copy, so a
// buggy multi-WIPE_OUTPUT scope trips the assertion on a normal pinned run, not just
// on the rare JVM-copy path. Compiled out under NDEBUG.
static thread_local int s_open_criticals = 0;
#endif

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

void JByteArrayCritical::cleanse_and_stash(
    uint8_t* src, jsize len, std::vector<uint8_t, SecureAlloc<uint8_t> >& dst)
{
    if (len <= 0) {
        return;
    }
    dst.assign(src, src + len);
    OPENSSL_cleanse(src, len);
}

JByteArrayCritical::JByteArrayCritical(JNIEnv* env, jbyteArray jarray, WipeMode mode)
    : ptr_(nullptr)
    , env_(env)
    , jarray_(jarray)
    , len_(0)
    , is_copy_(JNI_FALSE)
    , mode_(mode)
    , released_(false)
{
    len_ = env->GetArrayLength(jarray);

    ptr_ = env->GetPrimitiveArrayCritical(jarray, &is_copy_);
    if (ptr_ == nullptr) {
        throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
    }
#ifndef NDEBUG
    ++s_open_criticals;
#endif

    // Reserve stash capacity now that we know whether the JVM made a copy. Skipping this
    // allocation entirely on the pinned path (HotSpot's typical behavior) is the
    // optimization. release() must remain allocation-free and noexcept, so the reserve()
    // happens here rather than later -- but if it throws, the partially-constructed JBAC's
    // dtor won't run (ctor never finished), so we'd leak the critical region. Catch
    // bad_alloc, release the critical region ourselves, and rethrow to preserve the
    // original failure mode.
    if (mode_ == WipeMode::WIPE_OUTPUT && is_copy_ && len_ > 0) {
        try {
            stash_.reserve(static_cast<size_t>(len_));
        } catch (...) {
            env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, JNI_ABORT);
#ifndef NDEBUG
            --s_open_criticals;
#endif
            ptr_ = nullptr;
            throw java_ex(EX_OOM, "Failed to allocate stash buffer for sensitive output array");
        }
    }
}

JByteArrayCritical::~JByteArrayCritical()
{
    // RAII fallback for the single-WIPE_OUTPUT-per-scope case: end the critical region
    // and commit any stashed writes. Multi-WIPE_OUTPUT scopes must drive these manually
    // (see class comment); calls here will be no-ops if the caller already did.
    if (!released_) {
        release();
    }
    commitBack();
}

void JByteArrayCritical::release() noexcept
{
    if (released_) {
        return;
    }
    released_ = true;
#ifndef NDEBUG
    --s_open_criticals;
#endif

    // Pinned or non-sensitive: ptr_ aliases the Java array (or is opaque to us). Mode-0
    // release commits any writes that already landed in the array; for the pinned WIPE_*
    // paths we must not mutate the array, which mode 0 also satisfies (no rewrite occurs
    // when ptr_ IS the array).
    if (!is_copy_ || mode_ == WipeMode::NO_WIPE) {
        env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, 0);
        return;
    }

    // Wipe path on the JVM-copy variant. For WIPE_OUTPUT, stash the caller's writes
    // (allocation-free; capacity was reserved in the ctor). Cleanse the native copy in
    // both cases, then JNI_ABORT to free without copying the cleansed bytes back.
    if (mode_ == WipeMode::WIPE_OUTPUT) {
        JByteArrayCritical::cleanse_and_stash(static_cast<uint8_t*>(ptr_), len_, stash_);
    } else if (len_ > 0) { // WIPE_INPUT
        OPENSSL_cleanse(ptr_, len_);
    }
    env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, JNI_ABORT);
    // The stashed bytes (if any) are committed in commitBack(), which the dtor or
    // caller invokes after every critical region on the thread is closed.
}

void JByteArrayCritical::commitBack()
{
    if (mode_ != WipeMode::WIPE_OUTPUT || stash_.empty()) {
        return;
    }
    // Tripping this assertion means another JByteArrayCritical's critical region is
    // still open on this thread. SetByteArrayRegion is forbidden in that state. See the
    // class comment in buffer.h for the call-site pattern (single WIPE_OUTPUT per scope
    // declared first; multi-WIPE_OUTPUT requires manual release()/commitBack() ordering).
    //
    // Not directly unit-tested: assert() calls abort() on failure, which is incompatible
    // with the in-process test harness, and constructing a JByteArrayCritical needs a real
    // JNIEnv. Code review of new call sites is the primary defense; this assertion is the
    // backstop that fires in any debug-mode test run that misuses the API.
#ifndef NDEBUG
    assert(s_open_criticals == 0 && "commitBack() called while a critical region is still open on this thread");
#endif
    env_->SetByteArrayRegion(jarray_,
        0,
        static_cast<jsize>(stash_.size()),
        reinterpret_cast<const jbyte*>(stash_.data()));
    stash_.clear(); // idempotent: subsequent calls are no-ops
}

unsigned char* JByteArrayCritical::get()
{
    return released_ ? nullptr : static_cast<unsigned char*>(ptr_);
}

SimpleBuffer::SimpleBuffer(int size)
    : buffer_(nullptr)
{
    buffer_ = (uint8_t*)OPENSSL_malloc(size);
    if (buffer_ == nullptr) {
        throw java_ex(EX_ERROR, "malloc failed.");
    }
}

SimpleBuffer::~SimpleBuffer() { OPENSSL_free(buffer_); }

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

JIOBlobs::JIOBlobs(JNIEnv* env,
                   jobject inputDirectByteBuffer,
                   jbyteArray inputArray,
                   jobject outputDirectByteBuffer,
                   jbyteArray outputArray)
    : env_(env)
    , input_array_(inputArray)
    , output_array_(outputArray)
{
    // First, we need to deal with buffers that are direct ByteBuffers.
    if (inputDirectByteBuffer != nullptr) {
        // One should be null. In the Java layer, we ensure this.
        if (inputArray != nullptr) {
            throw java_ex(
                EX_ERROR,
                "THIS SHOULD NOT BE REACHABLE. Both inputDirectByteBuffer and inputArray cannot be provided.");
        }
        input_ptr_ = (uint8_t*)env->GetDirectBufferAddress(inputDirectByteBuffer);
    }

    if (outputDirectByteBuffer != nullptr) {
        // One should be null. In the Java layer, we ensure this.
        if (outputArray != nullptr) {
            throw java_ex(
                EX_ERROR,
                "THIS SHOULD NOT BE REACHABLE. Both outputDirectByteBuffer and outputArray cannot be provided.");
        }
        output_ptr_ = (inputDirectByteBuffer == outputDirectByteBuffer)
            ? input_ptr_
            : ((uint8_t*)env->GetDirectBufferAddress(outputDirectByteBuffer));
    }

    if (inputArray != nullptr) {
        input_ptr_ = (uint8_t*)env->GetPrimitiveArrayCritical(inputArray, nullptr);
        if (input_ptr_ == nullptr) {
            throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
        }
    }

    if (outputArray != nullptr) {
        // We should check if inputArray and outputArray are the same.
        if (inputArray == outputArray) {
            output_ptr_ = input_ptr_;
            // The output_array_ is set to null so that we do not call ReleasePrimitiveArrayCritical twice on the same
            // buffer.
            output_array_ = nullptr;
        } else {
            output_ptr_ = (uint8_t*)env->GetPrimitiveArrayCritical(outputArray, nullptr);
            if (output_ptr_ == nullptr) {
                // Throwing before ctor finishes, so dtor is never called. Must release input array.
                if (input_array_ != nullptr) {
                    env->ReleasePrimitiveArrayCritical(input_array_, input_ptr_, 0);
                }
                throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
            }
        }
    }
}

JIOBlobs::~JIOBlobs()
{
    if (input_array_ != nullptr) {
        env_->ReleasePrimitiveArrayCritical(input_array_, input_ptr_, 0);
    }

    if (output_array_ != nullptr) {
        env_->ReleasePrimitiveArrayCritical(output_array_, output_ptr_, 0);
    }

    // For direct ByteBuffers, there is no cleaning up.
}

uint8_t* JIOBlobs::get_input() { return input_ptr_; }

uint8_t* JIOBlobs::get_output() { return output_ptr_; }

} // end of namespace AmazonCorrettoCryptoProvider
