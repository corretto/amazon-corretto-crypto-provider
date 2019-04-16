// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <cstring> // for memset
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "generated-headers.h"
#include "util.h"
#include "bn.h"
#include "rsa.h"

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_RsaGen_generate(
        JNIEnv *pEnv,
        jclass,
        jint bits,
        jboolean checkConsistency,
        jbyteArray pubExp,
        jbyteArray modulusOut,
        jbyteArray privExpOut,
        jbyteArray primePOut,
        jbyteArray primeQOut,
        jbyteArray dmPOut,
        jbyteArray dmQOut,
        jbyteArray coefOut)
{
    RSA_auto r;

    try {
        raii_env env(pEnv);

        BigNumObj bne;
        jarr2bn(env, pubExp, bne);

        if (1 != RSA_generate_key_ex(r, bits, bne, NULL)) {
            throw_openssl("Unable to generate key");
        }
        
        if (checkConsistency && RSA_check_key(r) != 1) {
            throw_openssl("Key failed consistency check");
        }

        bn2jarr(env, modulusOut, r->n);
        bn2jarr(env, privExpOut, r->d);
        bn2jarr(env, primePOut, r->p);
        bn2jarr(env, primeQOut, r->q);
        bn2jarr(env, dmPOut, r->dmp1);
        bn2jarr(env, dmQOut, r->dmq1);
        bn2jarr(env, coefOut, r->iqmp);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}
