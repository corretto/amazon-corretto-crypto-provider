// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpMlDsaPublicKey extends EvpMlDsaKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpMlDsaPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpMlDsaPublicKey(final InternalKey key) {
    super(key, true);
  }
}
