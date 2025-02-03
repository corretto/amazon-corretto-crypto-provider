// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

/**
 * This class is used in AesGcmSpi and AesCbcSpi to ensure EVP_CIPHER_CTX that is associated to a
 * Cipher object is properly cleaned.
 */
final class NativeEvpCipherCtx extends NativeResource {
  NativeEvpCipherCtx(final long ptr) {
    super(ptr, Utils::releaseEvpCipherCtx);
  }
}
