// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class KeyGenRsa {
  @Param({"2048", "4096"})
  public int bits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunRsaSign"})
  public String provider;

  private KeyPairGenerator kpg;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    kpg = KeyPairGenerator.getInstance("RSA", provider);
    kpg.initialize(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4));
  }

  @Benchmark
  public KeyPair generate() {
    return kpg.generateKeyPair();
  }
}
