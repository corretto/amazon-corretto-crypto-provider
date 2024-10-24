// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

public class EvpHpkePublicKey extends EvpHpkeKey implements PublicKey {
  private static final long serialVersionUID = 1;

  EvpHpkePublicKey(InternalKey key, HpkeParameterSpec spec) {
    super(key, true, spec);
  }
}
