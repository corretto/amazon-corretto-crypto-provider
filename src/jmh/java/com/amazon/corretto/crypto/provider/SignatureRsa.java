// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class SignatureRsa extends SignatureBase {
  @Param({"SHA-1"})
  public String hash;

  @Param({"2048", "4096"})
  public int bits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunRsaSign"})
  public String provider;

  @Setup
  public void setup() throws Exception {
    final RSAKeyGenParameterSpec keyParams =
        new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4);
    final PSSParameterSpec sigParams =
        new PSSParameterSpec(
            hash,
            PSSParameterSpec.DEFAULT.getMGFAlgorithm(),
            PSSParameterSpec.DEFAULT.getMGFParameters(),
            PSSParameterSpec.DEFAULT.getSaltLength(),
            PSSParameterSpec.DEFAULT.getTrailerField());
    super.setup(provider, "RSA", keyParams, "RSASSA-PSS", sigParams);
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
