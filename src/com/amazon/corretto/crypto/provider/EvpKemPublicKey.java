// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpKemPublicKey extends EvpKemKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpKemPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpKemPublicKey(final InternalKey key) {
    super(key, true);
  }
}
