// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

final class NativeEvpCipherCtx extends NativeResource {
  NativeEvpCipherCtx(final long ptr) {
    super(ptr, Utils::releaseEvpCipherCtx);
  }
}
