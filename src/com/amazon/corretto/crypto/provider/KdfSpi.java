// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

abstract class KdfSpi extends SecretKeyFactorySpi {

  // A subclass cannot widen a throws clause its base narrowed, and the PBKDF2 subclass, which
  // does implement these, reports both.
  @Override
  protected KeySpec engineGetKeySpec(final SecretKey key, final Class<?> keySpec)
      throws InvalidKeySpecException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected SecretKey engineTranslateKey(final SecretKey key) throws InvalidKeyException {
    throw new UnsupportedOperationException();
  }
}
