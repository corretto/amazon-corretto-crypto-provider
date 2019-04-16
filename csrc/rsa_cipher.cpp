// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "generated-headers.h"
#include "util.h"
#include "bn.h"
#include "rsa.h"

using namespace AmazonCorrettoCryptoProvider;

namespace {

BIGNUM *opt_jarr2bn(raii_env &env, jbyteArray array) {
    BIGNUM *ret = NULL;
    if (array) {
        ret = BN_new();

        try {
            jarr2bn(env, array, ret);
        } catch (...) {
            BN_clear_free(ret);
            throw;
        }
    }

    return ret;
}

} // anonymous namespace

/*
 * Class:     com_amazon_corretto_crypto_provider_RsaCipher
 * Method:    releaseNativeKey
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_RsaCipher_releaseNativeKey(
    JNIEnv *,
    jclass,
    jlong keyPtr)
{
    // The destructor for RSA_auto will clean up the RSA structure for us.
    RSA_auto(reinterpret_cast<RSA *>(keyPtr));
}

JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_RsaCipher_cipher(
    JNIEnv *pEnv,
    jclass,
    jint mode,
    jbyteArray input,
    jint inOff,
    jint inLength,
    jbyteArray output,
    jint outOff,
    jint padding,
    jboolean checkPrivateKey,
    jlongArray keyHandle,
    jint handleMode,
    jbyteArray n,
    jbyteArray e,
    jbyteArray d,
    jbyteArray p,
    jbyteArray q,
    jbyteArray dmp1,
    jbyteArray dmq1,
    jbyteArray iqmp

)
{

    try {
        raii_env env(pEnv);

        RSA_auto backing; // Used for auto-cleanup
        RSA* r = (RSA *) backing;
        switch (handleMode) {
        case com_amazon_corretto_crypto_provider_RsaCipher_HANDLE_USAGE_IGNORE: // fallthrough
        case com_amazon_corretto_crypto_provider_RsaCipher_HANDLE_USAGE_CREATE:
            r->n = opt_jarr2bn(env, n);
            r->e = opt_jarr2bn(env, e);
            r->d = opt_jarr2bn(env, d);
            r->p = opt_jarr2bn(env, p);
            r->q = opt_jarr2bn(env, q);
            r->dmp1 = opt_jarr2bn(env, dmp1);
            r->dmq1 = opt_jarr2bn(env, dmq1);
            r->iqmp = opt_jarr2bn(env, iqmp);

            // If it is a private key, we check it for consistency, if possible and requested
            if (checkPrivateKey && d != NULL && p != NULL && q != NULL) {
                if (RSA_check_key(r) != 1) {
                    throw_openssl("java/security/InvalidKeyException", "Invalid key");
                }
            }

            // Set proper blinding on the key
            if (e && d) {
                // We can only blind keys with a public exponent and private parts
                if (!RSA_blinding_on(r, NULL)) {
                    throw_openssl("Unable to enable blinding");
                }
            } else {
                // Blinding isn't supported in this case and must
                // be explicitly disabled
                RSA_blinding_off(r);
            }
            break;
        case com_amazon_corretto_crypto_provider_RsaCipher_HANDLE_USAGE_USE:
            jlong tmpPtr;
            env->GetLongArrayRegion(keyHandle, 0, 1, &tmpPtr);
            r = reinterpret_cast<RSA *>(tmpPtr);
            break;
        default:
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected handle mode");
        }

        if (!r) {
            throw_java_ex(EX_NPE, "Null RSA key");
        }
        if (!input) {
            throw_java_ex(EX_NPE, "Null input array");
        }
        if (!output) {
            throw_java_ex(EX_NPE, "Null output array");
        }

        java_buffer inBuf = java_buffer::from_array(env, input, inOff, inLength);
        java_buffer outBuf = java_buffer::from_array(env, output, outOff, RSA_size(r));
        int len = 0;

        {
            jni_borrow in(env, inBuf, "input buffer");
            jni_borrow out(env, outBuf, "output buffer");

            switch (mode) {
            case 2: // Decrypt
            case 4: // Unwrap
                len = RSA_private_decrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case 1: // Encrypt
            case 3: // Wrap
                len = RSA_public_encrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case -1: // Encrypt with a private key, a.k.a. signing
                len = RSA_private_encrypt(inLength, in.data(), out.data(), r, padding);
                break;
            case -2: // Decrypt with a public key, a.k.a verification
                len = RSA_public_decrypt(inLength, in.data(), out.data(), r, padding);
                break;
            default:
                throw_java_ex(EX_RUNTIME_CRYPTO, "Unknown cipher mode");
            }

            if (len < 0) {
                unsigned long errCode = drainOpensslErrors();
                char errBuf[120];
                ERR_error_string_n(errCode, errBuf, sizeof(errBuf));

                // Ensure the buffer is null-terminated even if the message is truncated.
                errBuf[sizeof(errBuf)-1] = 0;

                if (errCode == ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_EAY_PUBLIC_ENCRYPT, RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
                  || errCode == ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
                  || errCode == ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2, RSA_R_PKCS_DECODING_ERROR)
                  || errCode == ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_PADDING_CHECK_FAILED)
                  || errCode == ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, RSA_R_OAEP_DECODING_ERROR)) {
                    throw_java_ex(EX_BADPADDING, errBuf);
                } else {
                    throw_java_ex(EX_RUNTIME_CRYPTO, errBuf);
                }
            }
        }
        if (handleMode == com_amazon_corretto_crypto_provider_RsaCipher_HANDLE_USAGE_CREATE) {
            jlong tmpPtr = reinterpret_cast<jlong>(backing.take());
            env->SetLongArrayRegion(keyHandle, 0, 1, &tmpPtr);
        }
        return len;
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

