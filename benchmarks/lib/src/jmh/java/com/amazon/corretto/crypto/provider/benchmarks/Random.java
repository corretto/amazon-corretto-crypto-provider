// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;

/**
 * Benchmark Random/SecureRandom implementations
 *
 * <p>Use average time in ns/op to measure the time per thread instead of the default throughput
 * mode (ops/s), because the throughput mode sums the number of operations over all the threads
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class Random {
  @State(Scope.Thread)
  public static class ThreadState {
    @Param({"4", "1024"})
    public int size;

    // data is a thread-local variable to prevent L1 cache contention
    // benchmarks generating randomness store it in data
    private byte[] data;
    // sourceData is a random array used as source data for baseline benchmarks
    // where sourceData is just copied to data
    private byte[] sourceData;

    @Setup
    public void setup() {
      data = new byte[size];
      sourceData = new byte[size];
      // generating sourceData at random to prevent potential optimizations
      (new java.util.Random()).nextBytes(sourceData);
    }
  }

  @State(Scope.Benchmark)
  public static class Shared {
    // !!! WARNING: java.util.random is not a secure randomness generator
    // !!! WARNING: we add it here just for comparison
    @Param({
      AmazonCorrettoCryptoProvider.PROVIDER_NAME + "/DEFAULT",
      "BC/DEFAULT",
      "SUN/NativePrng",
      "SUN/DRBG",
      "java.util.Random"
    })
    public String provider_algorithm;

    private String provider;
    private String algorithm;

    // random is shared amongst all threads
    private java.util.Random random;

    // localRandom is thread local
    private ThreadLocal<java.util.Random> localRandom;

    @Setup
    public synchronized void setup() throws Exception {
      if ("java.util.Random".equals(provider_algorithm)) {
        // java.util.random is a special case as it's not a SecureRandom
        random = new java.util.Random();
        // !!! WARNING: This is just for benchmarking and should not be used as is.
        //     Use ThreadLocalRandom.current() for a thread-local non-cryptographic randomness
        // generator
        localRandom = new ThreadLocal<java.util.Random>();
      } else {
        final String[] parts = provider_algorithm.split("/", 2);
        provider = parts[0];
        algorithm = parts[1];

        BenchmarkUtils.setupProvider(provider);

        random = SecureRandom.getInstance(algorithm, provider);
        localRandom =
            ThreadLocal.withInitial(
                () -> {
                  try {
                    return SecureRandom.getInstance(algorithm, provider);
                  } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    throw new RuntimeException(e);
                  }
                });
      }
    }
  }

  @Benchmark
  @Threads(1)
  public byte[] singleThreaded(Shared shared, ThreadState threadState) {
    shared.random.nextBytes(threadState.data);
    return threadState.data;
  }

  /** Benchmark the time needed to get a new instance */
  @Benchmark
  @Threads(1)
  public Object singleThreadedNew(Shared shared)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    if ("java.util.Random".equals(shared.provider_algorithm)) {
      return new Random();
    } else {
      return SecureRandom.getInstance(shared.algorithm, shared.provider);
    }
  }

  /**
   * Benchmark of SecureRandom with number of threads = number of hardware threads where
   * SecureRandom is shared between all threads
   */
  @Benchmark
  @Threads(Threads.MAX)
  public byte[] multiThreaded(Shared shared, ThreadState threadState) {
    shared.random.nextBytes(threadState.data);
    return threadState.data;
  }

  /**
   * Benchmark of SecureRandom with number of threads = number of hardware threads where
   * SecureRandom is local to each thread
   */
  @Benchmark
  @Threads(Threads.MAX)
  public byte[] multiThreadedLocal(Shared shared, ThreadState threadState) {
    shared.localRandom.get().nextBytes(threadState.data);
    return threadState.data;
  }

  /**
   * Benchmark of creating a new thread and generate randomness This benchmark is only to find
   * potential regressions due to per-thread initialization done by SecureRandom
   *
   * <p>Note that there will be L1 cache contention because `data` is shared between all the threads
   */
  @Benchmark
  @Threads(1)
  public byte[] newThreadPerRequest(Shared shared, ThreadState threadState)
      throws InterruptedException {
    Thread t = new Thread(() -> shared.random.nextBytes(threadState.data));
    t.start();
    t.join();
    return threadState.data;
  }

  /**
   * Baseline version of the {@link #singleThreaded singleThreaded} benchmark where instead of
   * generating randomness, data is copied from sourceData to data
   */
  @Benchmark
  @Threads(1)
  public byte[] singleThreadedBaseline(ThreadState threadState) {
    System.arraycopy(threadState.sourceData, 0, threadState.data, 0, threadState.size);
    return threadState.data;
  }

  /**
   * Baseline version of the {@link #multiThreaded multiThreaded} benchmark where instead of
   * generating randomness, data is copied from sourceData to data
   */
  @Benchmark
  @Threads(Threads.MAX)
  public byte[] multiThreadedBaseline(ThreadState threadState) {
    System.arraycopy(threadState.sourceData, 0, threadState.data, 0, threadState.size);
    return threadState.data;
  }

  /**
   * Baseline version of the {@link #newThreadPerRequest} newThreadPerRequest} benchmark where
   * instead of generating randomness, data is copied from sourceData to data
   */
  @Benchmark
  @Threads(1)
  public byte[] newThreadPerRequestBaseline(ThreadState threadState) throws InterruptedException {
    Thread t =
        new Thread(
            () ->
                System.arraycopy(threadState.sourceData, 0, threadState.data, 0, threadState.size));
    t.start();
    t.join();
    return threadState.data;
  }
}
