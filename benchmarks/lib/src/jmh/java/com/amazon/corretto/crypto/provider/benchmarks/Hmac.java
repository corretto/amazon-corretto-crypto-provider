// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class Hmac {
  @Param({"SHA256", "SHA384", "SHA512"})
  public String hash;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
  public String provider;

  private byte[] data_8B;
  private byte[] data_1KiB;
  private byte[] data_64KiB;
  private Mac mac;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    final String algorithm = "Hmac" + hash;
    data_8B = BenchmarkUtils.getRandBytes(8);
    data_1KiB = BenchmarkUtils.getRandBytes(1024);
    data_64KiB = BenchmarkUtils.getRandBytes(64 * 1024);
    mac = Mac.getInstance(algorithm, provider);
    mac.init(new SecretKeySpec(BenchmarkUtils.getRandBytes(mac.getMacLength()), algorithm));
  }

  @Benchmark
  public byte[] oneShotSmall_8B() {
    return mac.doFinal(data_8B);
  }

  @Benchmark
  public byte[] oneShotMedium_1KiB() {
    return mac.doFinal(data_1KiB);
  }

  @Benchmark
  public byte[] oneShotMedium_64KiB() {
    return mac.doFinal(data_64KiB);
  }
}
