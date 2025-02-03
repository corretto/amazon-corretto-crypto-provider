// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import javax.crypto.Cipher;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class AesGcmUpdate extends AesGcmBase {
  @Param({"128", "256"})
  public int keyBits;

  @Param({"16", "256"})
  public int chunkSize;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  @Setup
  public void setup() throws Exception {
    super.setup(keyBits, provider);
    assert PLAINTEXT_SIZE % chunkSize == 0;
  }

  @Benchmark
  public byte[] updateEncrypt() throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    for (int ii = 0; ii < plaintext.length; ii += chunkSize) {
      encryptor.update(plaintext, ii, chunkSize);
    }
    byte[] out = encryptor.doFinal();
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    return out;
  }

  @Benchmark
  public byte[] updateDecrypt() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    for (int ii = 0; ii < plaintext.length; ii += chunkSize) {
      decryptor.update(ciphertext, ii, chunkSize);
    }
    // don't forget to include the auth tag
    decryptor.update(ciphertext, plaintext.length, ciphertext.length - plaintext.length);
    byte[] out = decryptor.doFinal();
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
    return out;
  }
}
