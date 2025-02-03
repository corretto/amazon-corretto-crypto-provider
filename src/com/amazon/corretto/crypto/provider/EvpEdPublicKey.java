// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class EvpEdPublicKey extends EvpEdKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpEdPublicKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpEdPublicKey(final InternalKey key) {
    super(key, true);
  }
}
