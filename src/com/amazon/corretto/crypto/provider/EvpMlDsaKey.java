// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

abstract class EvpMlDsaKey extends EvpKey {
  private static final long serialVersionUID = 1;

  EvpMlDsaKey(InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.MlDSA, isPublicKey);
  }
}
