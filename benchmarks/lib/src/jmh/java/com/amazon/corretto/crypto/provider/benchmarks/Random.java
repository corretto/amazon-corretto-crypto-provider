// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.SecureRandom;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;

@State(Scope.Benchmark)
public class Drbg {
  @Param({"1024"})
  public int size;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SUN"})
  public String provider;

  private byte[] data;
  private SecureRandom random;

  @Setup
  public void setup() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    data = new byte[size];
    final String algorithm;
    switch (provider) {
      case AmazonCorrettoCryptoProvider.PROVIDER_NAME:
      case "BC":
        algorithm = "DEFAULT";
        break;
      case "SUN":
        algorithm = "DRBG";
        break;
      default:
        throw new RuntimeException("Unknown algorithm for provider " + provider);
    }
    random = SecureRandom.getInstance(algorithm, provider);
  }

  @Benchmark
  @Threads(1)
  public byte[] singleThreaded() {
    random.nextBytes(data);
    return data;
  }

  @Benchmark
  @Threads(Threads.MAX)
  public byte[] multiThreaded() {
    random.nextBytes(data);
    return data;
  }

  @Benchmark
  @Threads(1)
  public byte[] newThreadPerRequest() throws InterruptedException {
    Thread t =
        new Thread() {
          public void run() {
            random.nextBytes(data);
          }
        };
    t.start();
    t.join();
    return data;
  }
}
