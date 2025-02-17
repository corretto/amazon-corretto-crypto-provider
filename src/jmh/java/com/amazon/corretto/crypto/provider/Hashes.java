// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.MessageDigest;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class Hashes {
  @Param({"SHA-256", "SHA-384", "SHA-512"})
  public String algorithm;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SUN"})
  public String provider;

  private byte[] data_8B;
  private byte[] data_1KiB;
  private byte[] data_64KiB;
  private MessageDigest digest;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    data_8B = BenchmarkUtils.getRandBytes(8);
    data_1KiB = BenchmarkUtils.getRandBytes(1024);
    data_64KiB = BenchmarkUtils.getRandBytes(64 * 1024);
    digest = MessageDigest.getInstance(algorithm, provider);
  }

  @Benchmark
  public byte[] oneShotSmall_8B() {
    return digest.digest(data_8B);
  }

  @Benchmark
  public byte[] oneShotMedium_1KiB() {
    return digest.digest(data_1KiB);
  }

  @Benchmark
  public byte[] oneShotMedium_64KiB() {
    return digest.digest(data_64KiB);
  }
}
