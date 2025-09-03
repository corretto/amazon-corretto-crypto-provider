// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

public class EvpKemPublicKey extends EvpKemKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpKemPublicKey(final long ptr, final EvpKeyType type) {
    this(new InternalKey(ptr), type);
  }

  EvpKemPublicKey(final InternalKey key, final EvpKeyType type) {
    super(key, type, true);
  }
}
