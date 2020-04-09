// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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

        const BIGNUM *n;
        const BIGNUM *e;
        const BIGNUM *d;
        const BIGNUM *p;
        const BIGNUM *q;
        const BIGNUM *dmp1;
        const BIGNUM *dmq1;
        const BIGNUM *iqmp;
        RSA_get0_key(r, &n, &e, &d);
        RSA_get0_factors(r, &p, &q);
        RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);

        bn2jarr(env, modulusOut, n);
        bn2jarr(env, privExpOut, d);
        bn2jarr(env, primePOut, p);
        bn2jarr(env, primeQOut, q);
        bn2jarr(env, dmPOut, dmp1);
        bn2jarr(env, dmQOut, dmq1);
        bn2jarr(env, coefOut, iqmp);
    } catch (java_ex &ex) {
        ex.throw_to_java(pEnv);
    }
}
