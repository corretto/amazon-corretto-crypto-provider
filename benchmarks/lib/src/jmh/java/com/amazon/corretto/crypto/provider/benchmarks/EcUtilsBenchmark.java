// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.utils.EcUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
public class EcUtilsBenchmark {
  private PrivateKey accpPrivateKey;
  private PrivateKey bcPrivateKey;

  @Setup
  public void setup() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", AmazonCorrettoCryptoProvider.INSTANCE);
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair keyPair = kpg.generateKeyPair();
    accpPrivateKey = keyPair.getPrivate();

    kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    keyPair = kpg.generateKeyPair();
    bcPrivateKey = keyPair.getPrivate();
  }

  @Benchmark
  public byte[] accpRfc5915EPrivateKeyEncoding() {
    return EcUtils.encodeRfc5915EcPrivateKey(accpPrivateKey);
  }

  @Benchmark
  public byte[] accpVanillaKeyEncoding() {
    return accpPrivateKey.getEncoded();
  }

  @Benchmark
  public byte[] bcRfc5915EPrivateKeyEncoding() {
    return EcUtils.encodeRfc5915EcPrivateKey(accpPrivateKey);
  }

  @Benchmark
  public byte[] bcVanillaKeyEncoding() {
    return bcPrivateKey.getEncoded();
  }
}
