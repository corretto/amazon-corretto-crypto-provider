// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

class EvpHpkeKey extends EvpKey {
  private static final long serialVersionUID = 1;

  EvpHpkeKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.HPKE, isPublicKey);
  }
}
