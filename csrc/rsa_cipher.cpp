// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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
        {
            // When used with a set0 method, memory ownership transfers to the receiving object.
            // Thus, after successful ownership transfer, we release ownership of the BIGNUMs.
            // Once the RSA key owns them, since it is an RSA_auto class, it cleans itself
            // up if it remains on the stack.
            BigNumObj bn_n = BigNumObj::fromJavaArray(env, n);
            BigNumObj bn_e = BigNumObj::fromJavaArray(env, e);
            BigNumObj bn_d = BigNumObj::fromJavaArray(env, d);
            BigNumObj bn_p = BigNumObj::fromJavaArray(env, p);
            BigNumObj bn_q = BigNumObj::fromJavaArray(env, q);
            BigNumObj bn_dmp1 = BigNumObj::fromJavaArray(env, dmp1);
            BigNumObj bn_dmq1 = BigNumObj::fromJavaArray(env, dmq1);
            BigNumObj bn_iqmp = BigNumObj::fromJavaArray(env, iqmp);

            if (!RSA_set0_key(r, bn_n, bn_e, bn_d)) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set key parameters");
            } else {
                bn_n.releaseOwnership();
                bn_e.releaseOwnership();
                bn_d.releaseOwnership();
            }

            if (p && q && !RSA_set0_factors(r, bn_p, bn_q)) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set key factors");
            } else {
                bn_p.releaseOwnership();
                bn_q.releaseOwnership();
            }

            if (dmp1 && dmq1 && iqmp && !RSA_set0_crt_params(r, bn_dmp1, bn_dmq1, bn_iqmp)) {
                throw_openssl(EX_RUNTIME_CRYPTO, "Unable to set key crt_params");
            } else {
                bn_dmp1.releaseOwnership();
                bn_dmq1.releaseOwnership();
                bn_iqmp.releaseOwnership();
            }

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
        }
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
                throw_openssl(EX_BADPADDING, "Unknown error");
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

