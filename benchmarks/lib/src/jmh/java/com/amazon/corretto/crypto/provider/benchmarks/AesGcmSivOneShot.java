// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Benchmarks for AES-GCM-SIV (RFC 8452) one-shot encrypt and decrypt. SunJCE does not implement
 * this algorithm, so only ACCP (backed by AWS-LC) and BouncyCastle are benchmarked here.
 */
@State(Scope.Benchmark)
public class AesGcmSivOneShot extends AesBase {
  @Param({"128", "256"})
  public int keyBits;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC"})
  public String provider;

  @Param({"NoPadding"})
  public String padding;

  @Setup
  public void setup() throws Exception {
    super.setup(keyBits, provider, padding);
  }

  @Override
  protected String getMode() {
    return "GCM-SIV";
  }

  @Override
  protected AlgorithmParameterSpec createParameterSpec(byte[] iv) {
    return new GCMParameterSpec(128, iv);
  }

  @Override
  protected int getIvSize() {
    return 12;
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
