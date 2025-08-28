// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

class EdGen extends EvpKeyPairGenerator {

  EdGen(AmazonCorrettoCryptoProvider provider) {
    super(provider);
  }

  @Override
  protected KeyFactory getKeyFactory() {
    KeyFactory kf = null;
    try {
      kf = KeyFactory.getInstance(EvpKeyType.EdDSA.jceName, "SunEC");
    } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
      // This case indicates that either:
      // 1.) The current JDK runtime version does not support EdDSA (i.e. JDK version <15) or
      // 2.) No SunEC is registered with JCA
    }
    return kf;
  }

  @Override
  protected long generateEvpKey() {
    return generateEvpKey(EvpKeyType.EdDSA.nativeValue);
  }
}
