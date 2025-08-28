// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.security.PrivateKey;

class EvpXECPrivateKey extends EvpXECKey
    implements PrivateKey, CanDerivePublicKey<EvpXECPublicKey> {

  private static final long serialVersionUID = 1;

  EvpXECPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpXECPrivateKey(final InternalKey key) {
    super(key, false);
  }

  @Override
  public EvpXECPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final EvpXECPublicKey result = new EvpXECPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }
}
