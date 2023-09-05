// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.Cipher;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class RsaCipherOneShot {
  @Param({"2048", "4096"})
  public int keyBits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  @Param({"Pkcs1Padding", "OAEPWithSHA-1AndMGF1Padding"})
  public String padding;

  protected KeyPair keyPair;
  protected Cipher encryptor;
  protected Cipher decryptor;
  protected byte[] plaintext;
  protected byte[] ciphertext;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    String rsaProvider = provider;
    if (provider.equals("SunJCE")) {
      rsaProvider = "SunRsaSign";
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", rsaProvider);
    kpg.initialize(new RSAKeyGenParameterSpec(keyBits, RSAKeyGenParameterSpec.F4));
    keyPair = kpg.generateKeyPair();

    final String algorithm = String.format("RSA/ECB/%s", padding);
    encryptor = Cipher.getInstance(algorithm, provider);
    decryptor = Cipher.getInstance(algorithm, provider);
    encryptor.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    decryptor.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

    plaintext = BenchmarkUtils.getRandBytes(keyBits / 8 / 2); // half the key size
    ciphertext = encryptor.doFinal(plaintext);
  }

  @Benchmark
  public byte[] oneShotEncrypt() throws Exception {
    encryptor.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    return encryptor.doFinal(plaintext);
  }

  @Benchmark
  public byte[] oneShotDecrypt() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    return decryptor.doFinal(ciphertext);
  }
}
