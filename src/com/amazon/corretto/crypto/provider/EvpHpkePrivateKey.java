// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.security.PrivateKey;

public class EvpHpkePrivateKey extends EvpHpkeKey
    implements PrivateKey, CanDerivePublicKey<EvpHpkePublicKey> {
  private static final long serialVersionUID = 1;

  EvpHpkePrivateKey(InternalKey key) {
    super(key, false);
  }

  EvpHpkePrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  // Copied from EvpEcPrivateKey
  @Override
  public EvpHpkePublicKey getPublicKey() {
    // Once our internal key could be elsewhere, we can no longer safely release it when done
    ephemeral = false;
    sharedKey = true;
    final EvpHpkePublicKey result = new EvpHpkePublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }
}
