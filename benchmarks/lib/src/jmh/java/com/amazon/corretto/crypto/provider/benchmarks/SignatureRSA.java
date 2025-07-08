// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.spec.RSAKeyGenParameterSpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class SignatureRSA extends SignatureBase {
  @Param({"SHA256"})
  public String hash;

  @Param({"2048", "4096"})
  public int bits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunRsaSign"})
  public String provider;

  @Setup
  public void setup() throws Exception {
    final RSAKeyGenParameterSpec keyParams =
        new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4);
    final String sigAlg = hash + "withRSA";
    super.setup(provider, "RSA", keyParams, sigAlg, null);
  }

  @Benchmark
  public byte[] sign() throws Exception {
    return super.sign();
  }

  @Benchmark
  public boolean verify() throws Exception {
    return super.verify();
  }
}
