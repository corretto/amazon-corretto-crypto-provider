// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmBase {
  protected static final int PLAINTEXT_SIZE = 1024 * 1024;

  protected Key key;
  protected GCMParameterSpec params1;
  protected GCMParameterSpec params2;
  protected Cipher encryptor;
  protected Cipher decryptor;
  protected byte[] plaintext;
  protected byte[] ciphertext;

  protected void setup(int keyBits, String provider) throws Exception {
    BenchmarkUtils.setupProvider(provider);
    key = new SecretKeySpec(BenchmarkUtils.getRandBytes(keyBits / 8), "AES");
    params1 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    params2 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    final String algorithm = "AES/GCM/NoPadding";
    encryptor = Cipher.getInstance(algorithm, provider);
    decryptor = Cipher.getInstance(algorithm, provider);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    plaintext = BenchmarkUtils.getRandBytes(PLAINTEXT_SIZE);
    ciphertext = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
  }
}
