// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef UTIL_H
#define UTIL_H 1

#include "generated-headers.h"
#include "compiler.h"
#include "config.h"
#include <string.h>
#include <cstdlib>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <string>

namespace AmazonCorrettoCryptoProvider {

/* Drains all errors from the Openssl error queue and returns
 * just the most recent one. This should usually be used rather
 * than ERR_get_error.
 */
unsigned long drainOpensslErrors();

std::string formatOpensslError(unsigned long errorCode, const char *fallback);

inline std::string opensslErrorWithDefault(const char *fallback) {
    return formatOpensslError(drainOpensslErrors(), fallback);
}

#define EX_CLASSNOTFOUND "java/lang/NoClassDefFoundError"
#define EX_ERROR "java/lang/Error"
#define EX_OOM "java/lang/OutOfMemoryError"
#define EX_NPE "java/lang/NullPointerException"
#define EX_ARRAYOOB "java/lang/ArrayIndexOutOfBoundsException"
#define EX_INDEXOOB "java/lang/IndexOutOfBoundsException"
#define EX_BADPADDING "javax/crypto/BadPaddingException"
#define EX_SHORTBUFFER "javax/crypto/ShortBufferException"
#define EX_RUNTIME_CRYPTO "com/amazon/corretto/crypto/provider/RuntimeCryptoException"
#define EX_ILLEGAL_ARGUMENT "java/lang/IllegalArgumentException"
#define EX_ILLEGAL_STATE "java/lang/IllegalStateException"
#define EX_INVALID_KEY "java/security/InvalidKeyException"
#define EX_SIGNATURE_EXCEPTION "java/security/SignatureException"

// Define this prior to use as some compilers don't like it the other way around.
static inline void secureZero(void *ptr, size_t size) {
    if (ptr == nullptr || size == 0) {
      return;
    }
    memset(ptr, 0, size);
    __asm__ __volatile__(
        "" /* don't actually do anything */
        :  /* no outputs */
        : "r" (ptr) /* make the compiler think the memset matters */
        : "memory"  /* pretend we modify memory, so the compiler can't cache values in registers */
    );
}

template<typename type, size_t size>
class SecureBuffer {
  public:
    type buf[size];

    SecureBuffer() { secureZero(buf, sizeof(buf)); }
    virtual ~SecureBuffer() { zeroize(); }
    operator type*() {return buf; }
    operator const type*() const { return buf; }
    type& operator*() { return &buf; }
    const type& operator*() const { return &buf; }
    type& operator[](size_t idx) { return buf[idx]; }
    type& operator[](size_t idx) const { return buf[idx]; }
    virtual void zeroize() { secureZero(buf, sizeof(buf)); }
};

class EC_GROUP_auto {
public:
    EC_GROUP* group;

    EC_GROUP_auto(int nid) {
        group = EC_GROUP_new_by_curve_name(nid);
    }
    ~EC_GROUP_auto() {
        EC_GROUP_free(group);
    }
    operator EC_GROUP*() {return group; }
    operator const EC_GROUP*() const { return group; }
};

class pthread_lock_auto {
 public:
  pthread_mutex_t* lock;

  pthread_lock_auto(pthread_mutex_t* mutex) {
    lock = mutex;
    isLocked_ = (pthread_mutex_lock(lock) == 0);
    if (!isLocked_) {
      abort();
    }
  }

  ~pthread_lock_auto() {
    if (isLocked_) {
      pthread_mutex_unlock(lock);
    }
  }

  bool isLocked() {
    return isLocked_;
  }

  bool unlock() {
    if (isLocked_) {
      isLocked_ = (pthread_mutex_unlock(lock) != 0);
    }
    return !isLocked_;
  }

 private:
  bool isLocked_;
};

#if  __BYTE_ORDER == __LITTLE_ENDIAN
#if defined(__x86_64__)
// We need to continue supporting some old x86_64 build-chains, so we use a hand-rolled version of bswap64
static inline uint64_t swapEndian(uint64_t val) {
  uint64_t result = val;
  __asm__(
        "bswap %0"
       : "+r"(result)
  );
  return result;
}
#define hostToBigEndian64(x) swapEndian(x)
#define bigEndianToHost64(x) swapEndian(x)

#else
// For all other platforms (currently just aarch64), we know we are on a modern build-chain
// and can use the build-in function. (Also, the x86_64 assembly above won't work.)
#define hostToBigEndian64(x) __builtin_bswap64(x)
#define bigEndianToHost64(x) __builtin_bswap64(x)

#endif // Platform logic in __BYTE_ORDER == __LITTLE_ENDIAN

#else // __BYTE_ORDER == __BIG_ENDIAN
// No conversions are needed, so these methods become NOPs
#define hostToBigEndian64(x) (x)
#define bigEndianToHost64(x) (x)
#endif // BYTE_ORDER logic


static inline void* fast_xor(void* dest, const void* src, int len) {
    int idx = 0;
    uint8_t* dest8 = (uint8_t*) dest;
    uint8_t* src8 = (uint8_t*) src;
    for (; idx <= len - 8; idx += 8) {
        *((uint64_t*) (dest8 + idx)) ^= *((uint64_t*) (src8 + idx));
    }
    for (; idx < len; idx++) {
        dest8[idx] ^= src8[idx];
    }
    return dest;
}

/* Checks that the range of [offset, offset + range_len) fits within a buffer of size length */
static inline bool check_bounds(size_t length, size_t offset, size_t range_len) {
    if (unlikely(range_len > length)) {
        return false;
    }

    if (unlikely(offset > length)) {
        return false;
    }

    // Since offset <= length, we know this won't underflow
    size_t remaining = length - offset;
    return remaining >= range_len;

}

}

#endif

