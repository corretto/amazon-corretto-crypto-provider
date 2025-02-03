// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpMlDsaPrivateKey extends EvpMlDsaKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  EvpMlDsaPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpMlDsaPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpMlDsaPublicKey getPublicKey() {
    this.ephemeral = false;
    this.sharedKey = true;
    final EvpMlDsaPublicKey result = new EvpMlDsaPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }
}
