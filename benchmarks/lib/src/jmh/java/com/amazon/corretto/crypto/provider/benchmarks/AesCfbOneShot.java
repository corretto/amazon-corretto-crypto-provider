// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class AesCfbOneShot extends AesBase {
  @Param({"128", "256"})
  public int keyBits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  @Param({"NoPadding"})
  public String padding;

  @Setup
  public void setup() throws Exception {
    super.setup(keyBits, provider, padding);
  }

  @Override
  protected String getMode() {
    return "CFB";
  }

  @Override
  protected AlgorithmParameterSpec createParameterSpec(byte[] iv) {
    return new IvParameterSpec(iv);
  }

  @Override
  protected int getIvSize() {
    return 16;
  }

  @Benchmark
  public byte[] encrypt() throws Exception {
    return super.oneShot1MiBEncrypt();
  }

  @Benchmark
  public byte[] decrypt() throws Exception {
    return super.oneShot1MiBDecrypt();
  }
}
