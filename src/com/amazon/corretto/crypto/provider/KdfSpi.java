// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

abstract class KdfSpi extends SecretKeyFactorySpi {

  @Override
  protected KeySpec engineGetKeySpec(final SecretKey key, final Class<?> keySpec) {
    throw new UnsupportedOperationException();
  }

  @Override
  protected SecretKey engineTranslateKey(final SecretKey key) {
    throw new UnsupportedOperationException();
  }
}
