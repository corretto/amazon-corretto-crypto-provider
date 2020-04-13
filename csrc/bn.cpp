// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "bn.h"
#include "util.h"

namespace AmazonCorrettoCryptoProvider {

void jarr2bn(raii_env &env, jbyteArray array, BIGNUM *bn) {
    java_buffer buffer = java_buffer::from_array(env, array);

    jarr2bn(env, buffer, bn);
}

void jarr2bn(raii_env &env, const java_buffer &buffer, BIGNUM *bn) {
    jni_borrow borrow(env, buffer, "jarr2bn");

    BIGNUM *rv = BN_bin2bn((const uint8_t *)borrow.data(), borrow.len(), bn);

    if (unlikely(!rv)) {
        throw java_ex(EX_OOM, "Out of memory");
    }
}

void bn2jarr(raii_env &env, java_buffer &buffer, const BIGNUM *bn) {
    jni_borrow borrow(env, buffer, "bn2jarr");

    int bnLen = BN_num_bytes(bn);
    if (unlikely(bnLen < 0)) {
        throw_java_ex(EX_ERROR, "Bad bignum length");
    }
    size_t zero_prefix_len = borrow.len() - bnLen;
    memset(borrow.check_range(0, zero_prefix_len), 0, zero_prefix_len);

    BN_bn2bin(bn, borrow.check_range(zero_prefix_len, BN_num_bytes(bn)));
}

void bn2jarr(raii_env &env, jbyteArray array, const BIGNUM *bn) {
    java_buffer buf = java_buffer::from_array(env, array);
    bn2jarr(env, buf, bn);
}

} // namespace AmazonCorrettoCryptoProvider
