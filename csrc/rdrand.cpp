// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "config.h"
#include "util.h"
#include "env.h"
#include "buffer.h"
#include "generated-headers.h"
#include "rdrand.h"
#include "keyutils.h"
#include <openssl/evp.h>

#define DEFAULT_RETRY_COUNT 100

#ifdef ENABLE_RNG_TEST_HOOKS
extern "C" {
    bool (*hook_rdrand)(uint64_t *out) = NULL;
    bool (*hook_rdseed)(uint64_t *out) = NULL;
}

#else
#define hook_rdrand ((bool (*)(uint64_t *))NULL)
#define hook_rdseed ((bool (*)(uint64_t *))NULL)
#endif

using namespace AmazonCorrettoCryptoProvider;

namespace AmazonCorrettoCryptoProvider {

// Some inline machine-code which cannot always be represented
// by standard inline assembly mnemonics.

// rdrand %rcx
#define ASM_RDRAND_RCX ".byte 0x48, 0x0f, 0xc7, 0xf1\n"
// rdseed %rcx
#define ASM_RDSEED_RCX ".byte 0x48, 0x0f, 0xc7, 0xf9\n"
// PAUSE instruction. REP NOP
#define ASM_REP_NOP ".byte 0xf3, 0x90\n"

// We reuse these same macros for the test results
// of our RNGs stored in rng_tested
#define CPUID_PROBE_DONE (1 << 0)
#define CPUID_HAS_RDRAND (1 << 1)
#define CPUID_HAS_RDSEED (1 << 2)

volatile static uint32_t cpuid_info = 0;
volatile static uint32_t rng_tested = 0;

static inline int getCpuid(
        unsigned int level,
        unsigned int ecx_in,
        unsigned int* eax,
        unsigned int* ebx,
        unsigned int* ecx,
        unsigned int* edx) {
#if defined(__i386__) || defined(__x86_64__)
    unsigned int maxLevel = 0;
    unsigned int ignore_b, ignore_c, ignore_d;
    __asm__ __volatile__(
            "cpuid"
            : "=a"(maxLevel), "=b"(ignore_b), "=c"(ignore_c), "=d"(ignore_d)
            : "a"(0)
    );
    if (level > maxLevel) {
        return 0;
    }
    *ecx = ecx_in;
    __asm__ __volatile__(
            "cpuid"
            // Note: ECX is an in/out parameter as some CPUID levels care about both
            // EAX and ECX
            : "=a"(*eax), "=b"(*ebx), "+c"(*ecx), "=d"(*edx)
            : "a"(level)
    );
    return 1;
#else
    return 0;
#endif
}

void probe_cpuid() COLD NOINLINE;
void probe_cpuid() {
  uint32_t probe_info = CPUID_PROBE_DONE;

  unsigned int eax, ebx, ecx, edx;
  int result = getCpuid(1, 0, &eax, &ebx, &ecx, &edx);
  if (result == 0) {
    return;
  }

#if defined(__x86_64__) && !defined(FORCE_DISABLE_RDRAND)
  if (ecx & 0x40000000) {
      probe_info |= CPUID_HAS_RDRAND;
  }

  result = getCpuid(7, 0, &eax, &ebx, &ecx, &edx);
  if (result == 0) {
    return;
  }

  if (ebx & (1 << 18)) {
      probe_info |= CPUID_HAS_RDSEED;
  }
#endif // __x86_64__

  cpuid_info = probe_info;
}

uint32_t get_cpuinfo() {
  uint32_t info = cpuid_info;

  if (unlikely(!info)) {
    probe_cpuid();
    info = cpuid_info;
  }

  return info;
}

bool rng_rdrand(uint64_t *out) {
    if (unlikely(hook_rdrand)) {
        return (*hook_rdrand)(out);
    }

    bool success = 0;
    __asm__ __volatile__(
        ASM_RDRAND_RCX
        "setc %%al\n" // rax = 1 if success, 0 if fail
        : "=c" (*out), "=a" (success)
        : "c" (0), "a" (0)
        : "cc" // clobbers condition codes
    );

    // Some AMD CPUs will find that RDRAND "sticks" on all 1s but still reports success.
    // If we encounter this suspicious value (a 1/2^64 chance) we'll generate a second
    // value and compare it to the first. If they are equal (indicating it is stuck) then
    // we'll return an error. Else, we'll return the first value.
    // This reduces the risk of a false positive to 1/2^128 (negligible) and avoids biasing
    // the results at all as all 1s can still be returned by a valid RNG.
    // We also check for 0 as some old/non-standard systems may use that as an error value.

    if (likely(success)) {
      if (unlikely(*out == UINT64_MAX || *out == 0)) {
	uint64_t tmp;
	__asm__ __volatile__(
            ASM_RDRAND_RCX
	    "setc %%al\n" // rax = 1 if success, 0 if fail
	    : "=c" (tmp), "=a" (success)
	    : "c" (0), "a" (0)
	    : "cc" // clobbers condition codes
        );
	if (tmp == *out) {
	  *out = 0;
	  success = 0;
	}
      }
    }
    return success;
}

bool rng_rdseed(uint64_t *out) {
    if (unlikely(hook_rdseed)) {
        return (*hook_rdseed)(out);
    }

    // We don't call supportsRdSeed() here to avoid circular dependencies
    // during RNG testing.
    if (unlikely(!(get_cpuinfo() & CPUID_HAS_RDSEED))) {
        // We'll allow rdseed_fallback to poll rdrand instead
        *out = 0;
        return false;
    }

    bool success;
    __asm__ __volatile__(
	ASM_RDSEED_RCX
        "setc %%al\n" // rax = 1 if success, 0 if fail
        : "=c" (*out), "=a" (success)
        : "c" (0), "a" (0)
        : "cc" // clobbers condition codes
    );

    return success;
}

namespace {

void pause_and_decrement(int &counter) {
    __asm__ __volatile__(
    // Intel recommends putting the PAUSE instruction (REP NOP) between rdrand/rdseed polls
    // c.f. https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
    // (4.3.1.1)
    //
    // Unfortunately our ancient compilers don't like the PAUSE instruction - even when entered
    // as "rep nop", so we need to use raw machine code here as well.
        ASM_REP_NOP // PAUSE instruction
        "dec %0"   // decrement retry counter
        // prevent loop unrolling by hiding the loop decrement from the compiler
        : "+r" (counter)
        :
        : "cc"
    );
}

bool rdseed_fallback(uint64_t *dest) COLD NOINLINE;
bool rdseed_fallback(uint64_t *dest) {
    /* This routine performs a "512:1 reduction" as described in
     * https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
     * section 4.2.6.
     *
     * This involves taking 512 _128-bit_ samples of RDRAND and mixing them down to a single 128-bit sample
     * (which we then fold to a 64-bit sample). This guarantees reseeding by exceeding the 1022-sample limit
     * on the number of RDRAND samples generated by a single hardware-generated seed. Mixing is performed using
     * AES-128-CBC-MAC.
     *
     * As we sample RDRAND, we also retry sampling RDSEED in the hopes that it will recover and give us a result
     * faster.
     */
    
    // Buffers for key, IV, and data blocks
    uint8_t inbuf[16], outbuf[16], key[16], iv[16];
    bool success = false;
    int blockindex = 0, rdrand_retries_remain = 100;

    raii_cipher_ctx ctx;
    ctx.init();
    EVP_CIPHER_CTX_init(ctx);

    for (blockindex = 0; blockindex < (512 + 2) * 2; blockindex++) {
        // First, retry rdseed. Maybe it'll work this time?
        if (rng_rdseed(dest)) {
            success = true;
            goto out;
        }

        if (!rng_rdrand((uint64_t *)inbuf + (blockindex & 1))) {
            rdrand_retries_remain--;
            if (!rdrand_retries_remain) {
                goto out;
            }
            blockindex--; // retry getting this block
            continue;
        }

        if (!(blockindex & 1)) {
            // We loaded the first half of this 128-bit component, wait for the next
            continue;
        }

        int outl;
        switch (blockindex) {
            case 1: // Key loaded
                memcpy(key, inbuf, 16);
                memset(inbuf, 0, 16);
                break;
            case 3: // IV loaded
                memcpy(iv, inbuf, 16);
                memset(inbuf, 0, 16);

                if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
                    goto out;
                }

                if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
                    goto out;
                }

                break;
            default: // all other blocks are data to pump through
                if (!EVP_EncryptUpdate(ctx, outbuf, &outl, inbuf, sizeof(inbuf))) {
                    goto out;
                }

                if (outl != sizeof(outbuf)) {
                    abort(); // possible buffer overflow?
                }

                break;
        }
    }

    // At the end we should have a value in outbuf that is our reduced CBC-MAC value. Fold it and
    // present it as our result.
    // Note that we do this memcpy thing because directly addressing the buffer is technically
    // a strict aliasing violation.
    {
        uint64_t a, b;
        memcpy(&a, &outbuf[0], sizeof(a));
        memcpy(&b, &outbuf[8], sizeof(a));

        *dest = a ^ b;
        secureZero(&a, sizeof(a));
        secureZero(&b, sizeof(b));
    }
    success = true;
out:
    secureZero(inbuf, sizeof(inbuf));
    secureZero(outbuf, sizeof(outbuf));
    secureZero(key, sizeof(outbuf));
    secureZero(iv, sizeof(outbuf));

    if (!success) *dest = 0;

    return success;
}


bool rng_retry_rdrand(uint64_t *dest) {
    int tries = 10;

    do {
        if (likely(rng_rdrand(dest))) {
            return true;
        }

        pause_and_decrement(tries);
    } while(tries);

    return false;
}

bool rng_retry_rdseed(uint64_t *dest) {
    // First, try up to 32 times to get the result from rdseed directly
    // However, if RDSEED is not supported, bail out immediately and go to
    // the 512:1 reduction loop.
    int tries = supportsRdSeed() ? 32 : 0;

    while (tries) {
        if (likely(rng_rdseed(dest))) {
            return true;
        }

        pause_and_decrement(tries);
    }

    // Fall back into doing a 512:1 reduction on RDRAND
    return rdseed_fallback(dest);
}

bool rd_into_buf(bool (*rng)(uint64_t *), unsigned char *buf, int len) {
    unsigned char *original_buf = buf;
    int original_len = len;

    while (len >= 8) {
        if (unlikely(!rng(reinterpret_cast<uint64_t *>(buf)))) {
            goto fail;
        }

        buf += 8;
        len -= 8;
    }

    if (len) {
        uint64_t remain;
        if (unlikely(!rng(&remain))) {
            goto fail;
        }

        memcpy(buf, &remain, len);
        secureZero(&remain, 0);
    }

    return true;
fail:
    // Wipe the buffer to make sure it's obvious if something is ignoring the return value
    secureZero(original_buf, original_len);
    return false;
}

} // anon namespace

// C++ Exported methods:

void testRngs() COLD NOINLINE;
void testRngs() {
  uint32_t result = CPUID_PROBE_DONE;
  uint64_t scratch = 0; // No need to actually read this

  if (rng_rdrand(&scratch)) {
    result |= CPUID_HAS_RDRAND;
  }

  if (rng_rdseed(&scratch)) {
    result |= CPUID_HAS_RDSEED;
  }
  rng_tested = result;
}

uint32_t get_rng_tests() {
  uint32_t info = rng_tested;

  if (unlikely(!info)) {
    testRngs();
    info = rng_tested;
  }
  return info;
}

bool supportsRdRand() {
  return !!(get_cpuinfo() & CPUID_HAS_RDRAND) && !!(get_rng_tests() & CPUID_HAS_RDRAND);
}

bool supportsRdSeed() {
  return !!(get_cpuinfo() & CPUID_HAS_RDSEED) && !!(get_rng_tests() & CPUID_HAS_RDSEED);
}

bool rdseed(unsigned char *buf, int len) {
  return rd_into_buf(rng_retry_rdseed, buf, len);
}

bool rdrand(unsigned char *buf, int len) {
  return rd_into_buf(rng_retry_rdrand, buf, len);
}

} // namespace AmazonCorrettoCryptoProvider

// Java exported methods

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_rdrand
  (JNIEnv *pEnv, jclass, jbyteArray arr)
{
    try {
        raii_env env(pEnv);
        java_buffer buf = java_buffer::from_array(env, arr);
        jni_borrow borrow(env, buf, "borrow");

        return rdrand(borrow.data(), borrow.len());
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_rdseed
  (JNIEnv *pEnv, jclass, jbyteArray arr)
{
    try {
        raii_env env(pEnv);
        java_buffer buf = java_buffer::from_array(env, arr);
        jni_borrow borrow(env, buf, "borrow");

        return rdseed(borrow.data(), borrow.len());
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return false;
    }
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_PrivilegedTestHooks_set_1rng_1success_1pattern
  (JNIEnv *, jclass, jlong pattern)
{
    return false;
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_test_NativeTestHooks_hasRdseed
  (JNIEnv *, jclass)
{
    return supportsRdSeed();
}

JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_PrivilegedTestHooks_break_1rdseed
  (JNIEnv *, jclass)
{
    return false;
}
