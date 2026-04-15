// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Benchmarks for AES-GCM-SIV (RFC 8452) one-shot encrypt and decrypt. AES-GCM-SIV is only
 * supported by ACCP (backed by AWS-LC); SunJCE and BouncyCastle are not included as providers
 * since they do not implement this algorithm.
 */
@State(Scope.Benchmark)
public class AesGcmSivOneShot {
  private static final int PLAINTEXT_SIZE = 1024 * 1024;
  private static final String ALGORITHM = "AES/GCM-SIV/NoPadding";

  @Param({"128", "256"})
  public int keyBits;

  private Key key;
  private GCMParameterSpec params1;
  private GCMParameterSpec params2;
  private Cipher encryptor;
  private Cipher decryptor;
  private byte[] plaintext;
  private byte[] ciphertext;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    key = new SecretKeySpec(BenchmarkUtils.getRandBytes(keyBits / 8), "AES");
    params1 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    params2 = new GCMParameterSpec(128, BenchmarkUtils.getRandBytes(12));
    encryptor = Cipher.getInstance(ALGORITHM, AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    decryptor = Cipher.getInstance(ALGORITHM, AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    plaintext = BenchmarkUtils.getRandBytes(PLAINTEXT_SIZE);
    ciphertext = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
  }

  @Benchmark
  public byte[] encrypt() throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
    byte[] out = encryptor.doFinal(plaintext);
    encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
    return out;
  }

  @Benchmark
  public byte[] decrypt() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, params1);
    byte[] out = decryptor.doFinal(ciphertext);
    decryptor.init(Cipher.DECRYPT_MODE, key, params2);
    return out;
  }
}
