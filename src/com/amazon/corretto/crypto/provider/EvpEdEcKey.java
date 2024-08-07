// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

abstract class EvpEdEcKey extends EvpKey {
  private static final long serialVersionUID = 1;

  EvpEdEcKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.Ed25519, isPublicKey);
  }
}
