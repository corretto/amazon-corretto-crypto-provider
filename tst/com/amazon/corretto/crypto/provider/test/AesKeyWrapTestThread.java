// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class AesKeyWrapTestThread extends Thread {
  private final SecureRandom rnd_;
  private final List<SecretKey> keys_;
  private final Cipher enc_;
  private final Cipher dec_;
  private final int iterations_;
  private final byte[] plaintext_;
  public volatile Throwable result = null;

  public AesKeyWrapTestThread(
      List<String> cypherAliaces,
      String name,
      SecureRandom rng,
      int iterations,
      List<SecretKey> keys)
      throws GeneralSecurityException {
    super(name);
    iterations_ = iterations;
    keys_ = keys;
    enc_ = TestUtil.getCipher(TestUtil.NATIVE_PROVIDER, cypherAliaces);
    dec_ = TestUtil.getCipher(TestUtil.NATIVE_PROVIDER, cypherAliaces);
    plaintext_ = new byte[64];
    rnd_ = SecureRandom.getInstance("SHA1PRNG");
    byte[] seed = new byte[20];
    rng.nextBytes(seed);
    rnd_.setSeed(seed);
    rnd_.nextBytes(plaintext_);
  }

  @Override
  public void run() {
    for (int x = 0; x < iterations_; x++) {
      try {
        // Choose a key and encrypt the plaintext as if it were a key
        final SecretKey kek = keys_.get(rnd_.nextInt(keys_.size()));
        enc_.init(Cipher.ENCRYPT_MODE, kek);
        dec_.init(Cipher.DECRYPT_MODE, kek);
        assertArraysHexEquals(plaintext_, dec_.doFinal(enc_.doFinal(plaintext_)));

        // Then, pick a random key from the list and wrap/unwrap it
        final Key toWrap = keys_.get(rnd_.nextInt(keys_.size()));
        enc_.init(Cipher.WRAP_MODE, kek);
        dec_.init(Cipher.UNWRAP_MODE, kek);
        final Key unwrapped = dec_.unwrap(enc_.wrap(toWrap), "AES", Cipher.SECRET_KEY);
        assertArraysHexEquals(toWrap.getEncoded(), unwrapped.getEncoded());
      } catch (final Throwable ex) {
        result = ex;
        return;
      }
    }
  }
}
