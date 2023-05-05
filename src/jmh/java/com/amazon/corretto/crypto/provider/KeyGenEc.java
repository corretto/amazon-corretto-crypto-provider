// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class KeyGenEc {
  @Param({"secp256r1", "secp384r1", "secp521r1"})
  public String curve;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunEC"})
  public String provider;

  private KeyPairGenerator kpg;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    kpg = KeyPairGenerator.getInstance("EC", provider);
    kpg.initialize(new ECGenParameterSpec(curve));
  }

  @Benchmark
  public KeyPair generate() {
    return kpg.generateKeyPair();
  }
}
