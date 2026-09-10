// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

/**
 * Wrapper for a native EVP_AEAD_CTX pointer used by AesGcmSivSpi to ensure the context is properly
 * freed when no longer needed.
 */
final class NativeEvpAeadCtx extends NativeResource {
  NativeEvpAeadCtx(final long ptr) {
    super(ptr, Utils::releaseEvpAeadCtx);
  }
}
