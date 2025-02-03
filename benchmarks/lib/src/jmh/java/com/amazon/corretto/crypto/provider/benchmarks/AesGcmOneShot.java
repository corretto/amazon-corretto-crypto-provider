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
public class AesGcmOneShot extends AesGcmBase {
  @Param({"128", "256"})
  public int keyBits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  @Setup
  public void setup() throws Exception {
    super.setup(keyBits, provider);
  }

  @Benchmark
  public byte[] oneShot1MiBEncrypt() throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    byte[] out = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    return out;
  }

  @Benchmark
  public byte[] oneShot1MiBDecrypt() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    byte[] out = decryptor.doFinal(ciphertext);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
    return out;
  }
}
