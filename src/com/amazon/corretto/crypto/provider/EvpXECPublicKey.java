// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpXECPublicKey extends EvpXECKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpXECPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpXECPublicKey(final InternalKey key) {
    super(key, true);
  }
}
