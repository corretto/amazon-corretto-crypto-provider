// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpEdEcPublicKey extends EvpEdEcKey implements PublicKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPublicKey(long ptr);

  private volatile byte[] publicKey;

  EvpEdEcPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEdEcPublicKey(final InternalKey key) {
    super(key, true);
  }
}
