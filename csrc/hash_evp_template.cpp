#include <openssl/digest.h>
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
//Need to build out the template for this

//With regards to what is actually called, we need the get context size, get hash size, init, update context buffer and native buffer, finish, and fast digest functionalities

//These are exposed using the functions in digest.h 

// OPENSSL_EXPORT const EVP_MD *EVP_md4(void);
// OPENSSL_EXPORT const EVP_MD *EVP_md5(void);
// OPENSSL_EXPORT const EVP_MD *EVP_ripemd160(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha1(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha224(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha256(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha384(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha512(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha512_224(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha512_256(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha3_224(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha3_256(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha3_384(void);
// OPENSSL_EXPORT const EVP_MD *EVP_sha3_512(void);
// OPENSSL_EXPORT const EVP_MD *EVP_shake128(void);
// OPENSSL_EXPORT const EVP_MD *EVP_shake256(void);
// OPENSSL_EXPORT const EVP_MD *EVP_blake2b256(void);

//Need to write out a new template to work with the EVP template exposed in AWS-LC


//What would we need as a unique identifier for each use?
    //Just the function name 
    //Example: #define DIGEST_NAME sha3_224(Needs to be written in this format to align with the aws-lc implementation name)
    

#define JNI_NAME(name) CONCAT2( \
        CONCAT2(Java_com_amazon_corretto_crypto_provider_, DIGEST_NAME), \
        CONCAT2(Spi_, name) \
    )

#define MD CONCAT2(EVP_, DIGEST_NAME)
#define CTX EVP_MD_CTX


JNIEXPORT jint JNICALL JNI_NAME(getContextSize)(JNIEnv*, jclass) { return MD->ctx_size ; }

JNIEXPORT jint JNICALL JNI_NAME(getHashSize)(JNIEnv*, jclass) { return MD->md_size; }

JNIEXPORT void JNICALL JNI_NAME(initContext)(JNIEnv* pEnv, jclass, jbyteArray contextArray)
{
    try{
        raii_env env(pEnv)
        CTX ctx 

        java_buffer contextBuffer = java_buffer::from_array(env, contextArray)

        if (contextBuffer.len() != sizeof(ctx)){
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "Bad context buffer size");
        }
        
        CHECK_OPENSSL(EVP_DigestInit(&ctx, MD));
        contextBuffer.put_bytes(env, reinterpret_cast<const uint8_t*>(&ctx), 0, sizeof(ctx));
        } 
    catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL JNI_NAME(updateContextByteArray)(
    JNIEnv* pEnv, jclass, jbyteArray contextArray, jbyteArray dataArray, jint offset, jint length)
{
    try {
        raii_env env(pEnv);

        bounce_buffer<CTX> ctx = bounce_buffer<CTX>::from_array(env, contextArray);

        try {
            java_buffer databuf = java_buffer::from_array(env, dataArray, offset, length);
            jni_borrow dataBorrow(env, databuf, "databuf");
            
            CHECK_OPENSSL(EVP_DigestUpdate(ctx.ptr(), dataBorrow.data(), dataBorrow.len()));

        } catch (...) {
            ctx.zeroize();
            throw;
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


JNIEXPORT void JNICALL JNI_NAME(finish)(
    JNIEnv* pEnv, jclass, jbyteArray contextArray, jbyteArray digestArray, jint offset)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<CTX> ctx = bounce_buffer<CTX>::from_array(env, contextArray);

        java_buffer digestbuf = java_buffer::from_array(env, digestArray);
        jni_borrow digestBorrow(env, digestbuf, "digestbuf");

        int success = CHECK_OPENSSL(EVP_DigestFinal(digestBorrow.check_range(offset, MD->md_size), ctx));

        // Always clear the context on final()
        ctx.zeroize();

        if (unlikely(!success)) {
            digestBorrow.zeroize();
            throw_openssl();
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}


JNIEXPORT void JNICALL JNI_NAME(updateNativeByteBuffer)(
    JNIEnv* pEnv, jclass, jbyteArray contextArray, jobject dataDirectBuf)
{
    try {
        raii_env env(pEnv);
        bounce_buffer<CTX> ctx = bounce_buffer<CTX>::from_array(env, contextArray);

        java_buffer dataBuf = java_buffer::from_direct(env, dataDirectBuf);
        jni_borrow dataBorrow(env, dataBuf, "dataBorrow");

        try {
            CHECK_OPENSSL(EVP_DigestUpdate(ctx.ptr(), dataBorrow.data(), dataBorrow.len()));
        } catch (...) {
            ctx.zeroize();
            throw;
        }
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}

JNIEXPORT void JNICALL JNI_NAME(fastDigest)(
    JNIEnv* pEnv, jclass, jbyteArray digestArray, jbyteArray dataArray, jint bufOffset, jint dataLength)
{
    // As this method needs to be extremely high speed, we are omitting use of java_buffer
    // to avoid the extra JNI calls it requires. Instead we are trusting that dataLength
    // is correct.
    try {
        raii_env env(pEnv);

        SecureBuffer<CTX, 1> ctx;
        const size_t scratchSize = DIGEST_BLOCK_SIZE; // Size is arbitrarily chosen
        SecureBuffer<uint8_t, MD->md_size > digest;

        if (unlikely(!EVP_DigestInit(ctx, MD))) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to initialize context");
        }

        if (static_cast<size_t>(dataLength) > scratchSize) {
            java_buffer dataBuffer = java_buffer::from_array(env, dataArray, bufOffset, dataLength);
            jni_borrow dataBorrow(env, dataBuffer, "data");
            if (unlikely(EVP_DigestUpdate(ctx, dataBorrow.data(), dataBorrow.len()))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to update context");
            }
        } else {
            SecureBuffer<uint8_t, scratchSize> scratch;
            env->GetByteArrayRegion(dataArray, bufOffset, dataLength, reinterpret_cast<jbyte*>(scratch.buf));
            if (unlikely(!EVP_DigestUpdate(ctx, scratch, dataLength))) {
                throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to update context");
            }
        }

        if (unlikely(!EVP_DigestFinal(ctx, digest, MD->md_size))) {
            throw java_ex::from_openssl(EX_RUNTIME_CRYPTO, "Unable to finish digest");
        }
        env->SetByteArrayRegion(digestArray, 0, MD->md_size , reinterpret_cast<const jbyte*>(digest.buf));

    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
}




