// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <vector>

#include "bn.h"
#include "util.h"

namespace AmazonCorrettoCryptoProvider
{

    void jarr2bn(raii_env &env, jbyteArray array, BIGNUM *bn)
    {
        java_buffer buffer = java_buffer::from_array(env, array);

        jarr2bn(env, buffer, bn);
    }

    void jarr2bn(raii_env &env, const java_buffer &buffer, BIGNUM *bn)
    {
        jni_borrow borrow(env, buffer, "jarr2bn");

        // Force value to be positive
        if (borrow.data()[0] & 0x80)
        {
            throw_java_ex(EX_ILLEGAL_ARGUMENT, "Value must be positive");
        }

        BIGNUM *rv = BN_bin2bn((const uint8_t *)borrow.data(), borrow.len(), bn);

        if (unlikely(!rv))
        {
            throw java_ex(EX_OOM, "Out of memory");
        }
    }

    void bn2jarr(raii_env &env, java_buffer &buffer, const BIGNUM *bn)
    {
        jni_borrow borrow(env, buffer, "bn2jarr");

        int bnLen = BN_num_bytes(bn);
        if (unlikely(bnLen < 0))
        {
            throw_java_ex(EX_ERROR, "Bad bignum length");
        }

        CHECK_OPENSSL(BN_bn2binpad(bn, borrow, borrow.len()) >= 0);
    }

    void bn2jarr(raii_env &env, jbyteArray array, const BIGNUM *bn)
    {
        java_buffer buf = java_buffer::from_array(env, array);
        bn2jarr(env, buf, bn);
    }

    jbyteArray bn2jarr(raii_env &env, const BIGNUM *bn)
    {
        const size_t bnLen = BN_num_bytes(bn);
        if (unlikely(bnLen < 0))
        {
            throw_java_ex(EX_ERROR, "Bad bignum length");
        }
        std::vector<uint8_t, SecureAlloc<uint8_t> > tmp(bnLen);

        BN_bn2bin(bn, &tmp[0]);

        jbyteArray jarr;
        if (!(jarr = env->NewByteArray(bnLen)))
        {
            throw_java_ex(EX_OOM, "Unable to allocate signature array");
        }

        env->SetByteArrayRegion(jarr, 0, bnLen, (jbyte *)&tmp[0]);
        env.rethrow_java_exception();
        return jarr;
    }

} // namespace AmazonCorrettoCryptoProvider
