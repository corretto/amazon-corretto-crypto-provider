// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public abstract class AesBase {
  protected static final int PLAINTEXT_SIZE = 1024 * 1024;

  protected Key key;
  protected AlgorithmParameterSpec params1;
  protected AlgorithmParameterSpec params2;
  protected Cipher encryptor;
  protected Cipher decryptor;
  protected byte[] plaintext;
  protected byte[] ciphertext;

  protected abstract String getMode();

  protected abstract AlgorithmParameterSpec createParameterSpec(byte[] iv);

  protected abstract int getIvSize();

  protected void setup(int keyBits, String provider, String padding) throws Exception {
    BenchmarkUtils.setupProvider(provider);
    key = new SecretKeySpec(BenchmarkUtils.getRandBytes(keyBits / 8), "AES");
    params1 = createParameterSpec(BenchmarkUtils.getRandBytes(getIvSize()));
    params2 = createParameterSpec(BenchmarkUtils.getRandBytes(getIvSize()));
    final String algorithm = "AES/" + getMode() + "/" + padding;
    encryptor = Cipher.getInstance(algorithm, provider);
    decryptor = Cipher.getInstance(algorithm, provider);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    plaintext = BenchmarkUtils.getRandBytes(PLAINTEXT_SIZE);
    ciphertext = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
  }

  public byte[] oneShot1MiBEncrypt() throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    byte[] out = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    return out;
  }

  public byte[] oneShot1MiBDecrypt() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    byte[] out = decryptor.doFinal(ciphertext);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
    return out;
  }

  public byte[] updateEncrypt(int chunkSize) throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    for (int ii = 0; ii < plaintext.length; ii += chunkSize) {
      encryptor.update(plaintext, ii, chunkSize);
    }
    byte[] out = encryptor.doFinal();
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    return out;
  }

  public byte[] updateDecrypt(int chunkSize) throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    for (int ii = 0; ii < plaintext.length; ii += chunkSize) {
      decryptor.update(ciphertext, ii, chunkSize);
    }
    // Don't forget to include the auth tag if applicable. This is a no-op
    // if plaintext and ciphertext are same length (i.e. no tag).
    decryptor.update(ciphertext, plaintext.length, ciphertext.length - plaintext.length);
    byte[] out = decryptor.doFinal();
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
    return out;
  }
}
