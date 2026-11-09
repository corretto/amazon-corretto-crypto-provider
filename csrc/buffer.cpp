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
// calls within a critical region" rule.
//
// "Pin vs. copy" refers to the two outcomes of GetPrimitiveArrayCritical, per the JNI
// spec: "If possible, the VM returns a pointer to the primitive array; otherwise, a
// copy is made." On the pin path commitBack() is a no-op because stash_ is empty (the
// release() call on a pinned, non-NO_WIPE buffer skips the stash step entirely; the
// pinned writes already landed in the Java array). The pin-vs-copy choice is made by
// the JVM and is rare in practice on HotSpot. Counting in this thread-local is
// independent of which outcome occurred, so a buggy multi-WIPE_OUTPUT scope trips the
// assertion even on a normal pinned run, not just on the rare JVM-copy path. Compiled
// out under NDEBUG.
//
// JNI spec reference:
// https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#GetPrimitiveArrayCritical_ReleasePrimitiveArrayCritical
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

// ---- Base class: non-sensitive critical region ----

JByteArrayCritical::JByteArrayCritical(JNIEnv* env, jbyteArray jarray)
    : ptr_(nullptr)
    , env_(env)
    , jarray_(jarray)
    , is_copy_(JNI_FALSE)
    , released_(false)
{
    ptr_ = env->GetPrimitiveArrayCritical(jarray, &is_copy_);
    if (ptr_ == nullptr) {
        throw java_ex(EX_ERROR, "GetPrimitiveArrayCritical failed.");
    }
#ifndef NDEBUG
    ++s_open_criticals;
#endif
}

JByteArrayCritical::~JByteArrayCritical()
{
    // RAII fallback. Subclass dtors must run their cleanup BEFORE this base dtor, since
    // doRelease() is dispatched through a virtual call -- by the time we reach ~JBAC, the
    // derived object's vtable slice is gone and a virtual call would resolve to the base.
    // SecretOutputArray::~SecretOutputArray() therefore calls release() itself before
    // chaining here.
    release();
}

void JByteArrayCritical::release() noexcept
{
    if (released_) {
        return;
    }
    released_ = true;
#ifndef NDEBUG
    assert(s_open_criticals > 0 && "release() called with negative open criticals, should never happen");
    --s_open_criticals;
#endif
    doRelease();
}

void JByteArrayCritical::doRelease() noexcept
{
    // Default base behavior: mode-0 release. Per JNI spec, mode 0 means "copy back any
    // modifications, then free the native buffer." For the pinned path ptr_ aliases the
    // Java array so there is nothing to copy back. See:
    // https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#ReleasePrimitiveArrayCritical
    env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, 0);
}

unsigned char* JByteArrayCritical::get()
{
    return released_ ? nullptr : static_cast<unsigned char*>(ptr_);
}

// ---- SecretInputArray: cleanse-on-release ----

SecretInputArray::SecretInputArray(JNIEnv* env, jbyteArray jarray, jsize len)
    : JByteArrayCritical(env, jarray)
    , len_(len)
{
}

void SecretInputArray::doRelease() noexcept
{
    if (is_copy_) {
        // Caller did not write through get(). Cleanse the native copy and discard via
        // JNI_ABORT to avoid mode-0's commit-back of zeros to the Java array.
        if (len_ > 0) {
            OPENSSL_cleanse(ptr_, len_);
        }
        env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, JNI_ABORT);
    } else {
        // Pinned: ptr_ aliases the Java array; mutating it is forbidden. Mode-0 release.
        env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, 0);
    }
}

// ---- SecretOutputArray: cleanse-and-stash, with deferred commit-back ----

SecretOutputArray::SecretOutputArray(JNIEnv* env, jbyteArray jarray, jsize len)
    : JByteArrayCritical(env, jarray)
    , len_(len)
{
    // Reserve stash capacity now (after we know is_copy_) so doRelease() is allocation-
    // free and noexcept. Skipping the allocation on the pinned path (HotSpot's typical
    // behavior) is a meaningful optimization. If reserve() throws, the base class has
    // already entered the critical region; we must release it ourselves before rethrow,
    // since the dtor of a partially-constructed-derived object will NOT run.
    if (is_copy_ && len_ > 0) {
        try {
            stash_.reserve(static_cast<size_t>(len_));
        } catch (...) {
            env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, JNI_ABORT);
#ifndef NDEBUG
            --s_open_criticals;
#endif
            ptr_ = nullptr;
            released_ = true; // mark released so base dtor skips its release()
            throw java_ex(EX_OOM, "Failed to allocate stash buffer for sensitive output array");
        }
    }
}

SecretOutputArray::~SecretOutputArray()
{
    // Run derived release() while our vtable is still intact (so doRelease() dispatches
    // to SecretOutputArray::doRelease, stashing bytes). Then commit any stashed bytes.
    // The base class dtor will call release() too, but it'll be a no-op (idempotent).
    release();
    commitBack();
}

void SecretOutputArray::doRelease() noexcept
{
    if (is_copy_) {
        // Stash the caller's writes (allocation-free; capacity reserved in the ctor),
        // cleanse the native copy, then JNI_ABORT to free without copying the cleansed
        // bytes back. The stash is committed later by commitBack().
        JByteArrayCritical::cleanse_and_stash(static_cast<uint8_t*>(ptr_), len_, stash_);
        env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, JNI_ABORT);
    } else {
        // Pinned: caller's writes already landed in the Java array; mode-0 release.
        env_->ReleasePrimitiveArrayCritical(jarray_, ptr_, 0);
    }
}

void SecretOutputArray::commitBack()
{
    // Tripping this assertion means another JByteArrayCritical's critical region is
    // still open on this thread. SetByteArrayRegion is forbidden in that state. See the
    // class comment in buffer.h for the call-site patterns.
    //
    // Not directly unit-tested: assert() calls abort() on failure, which is incompatible
    // with the in-process test harness, and constructing a SecretOutputArray needs a
    // real JNIEnv. Code review of new call sites is the primary defense; this assertion
    // is the backstop that fires in any debug-mode test run that misuses the API.
#ifndef NDEBUG
    assert(s_open_criticals == 0 && "commitBack() called while a critical region is still open on this thread");
#endif
    if (stash_.empty()) {
        return;
    }
    env_->SetByteArrayRegion(jarray_,
        0,
        static_cast<jsize>(stash_.size()),
        reinterpret_cast<const jbyte*>(stash_.data()));
    stash_.clear(); // idempotent: subsequent calls are no-ops
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
