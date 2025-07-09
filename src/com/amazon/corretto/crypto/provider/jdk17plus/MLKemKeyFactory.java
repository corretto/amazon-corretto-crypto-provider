// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.jdk17plus;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class MLKemKeyFactory extends KeyFactorySpi {

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    throw new UnsupportedOperationException("Not implemented yet");
  }
}
