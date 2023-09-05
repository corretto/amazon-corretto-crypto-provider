// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@Warmup(iterations = 4, time = 4)
@Measurement(iterations = 4, time = 4)
@Fork(value = 1)
public class AesXtsBenchmark {
  public static String TRANSFORMATION = "AES/XTS/NoPadding";

  @State(Scope.Benchmark)
  public static class BenchmarkState {
    @Param({"1048576", "16777216"})
    public int length;

    public SecretKey key;
    public IvParameterSpec tweak;
    public byte[] data;

    @Setup
    public void setup() throws Exception {
      final SecureRandom srand =
          SecureRandom.getInstance("DEFAULT", AmazonCorrettoCryptoProvider.INSTANCE);
      final byte[] keyBytes = new byte[64];
      srand.nextBytes(keyBytes);
      key = new SecretKeySpec(keyBytes, "AES-XTS");
      final byte[] tweakBytes = new byte[16];
      srand.nextBytes(tweakBytes);
      tweak = new IvParameterSpec(tweakBytes);
      data = new byte[length];
      srand.nextBytes(data);
    }
  }

  // The cipher text is written to the input buffer
  public byte[] enc(final SecretKey key, final IvParameterSpec tweak, final byte[] buffer)
      throws Exception {
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION, AmazonCorrettoCryptoProvider.INSTANCE);
    cipher.init(Cipher.ENCRYPT_MODE, key, tweak);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    return buffer;
  }

  // The plain text is written to the input buffer
  public byte[] dec(final SecretKey key, final IvParameterSpec tweak, final byte[] buffer)
      throws Exception {
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION, AmazonCorrettoCryptoProvider.INSTANCE);
    cipher.init(Cipher.DECRYPT_MODE, key, tweak);
    cipher.doFinal(buffer, 0, buffer.length, buffer);
    return buffer;
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OutputTimeUnit(TimeUnit.MILLISECONDS)
  public final void xtsSameBuffer(BenchmarkState state, Blackhole blackhole) throws Exception {
    final byte[] cipherText = enc(state.key, state.tweak, state.data);
    final byte[] plaintext = dec(state.key, state.tweak, cipherText);
    blackhole.consume(plaintext);
  }

  public byte[] encFresh(final SecretKey key, final IvParameterSpec tweak, final byte[] buffer)
      throws Exception {
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION, AmazonCorrettoCryptoProvider.INSTANCE);
    cipher.init(Cipher.ENCRYPT_MODE, key, tweak);
    return cipher.doFinal(buffer);
  }

  public byte[] decFresh(final SecretKey key, final IvParameterSpec tweak, final byte[] buffer)
      throws Exception {
    final Cipher cipher = Cipher.getInstance(TRANSFORMATION, AmazonCorrettoCryptoProvider.INSTANCE);
    cipher.init(Cipher.DECRYPT_MODE, key, tweak);
    return cipher.doFinal(buffer);
  }

  @Benchmark
  @BenchmarkMode(Mode.Throughput)
  @OutputTimeUnit(TimeUnit.MILLISECONDS)
  public final void xtsDiffBuffer(BenchmarkState state, Blackhole blackhole) throws Exception {
    final byte[] cipherText = encFresh(state.key, state.tweak, state.data);
    final byte[] plaintext = decFresh(state.key, state.tweak, cipherText);
    blackhole.consume(plaintext);
  }

  public static void main(String[] args) throws RunnerException {
    new Runner(
            new OptionsBuilder()
                .include(AesXtsBenchmark.class.getSimpleName())
                // .addProfiler(GCProfiler.class) // uncomment for GC profiling
                .build())
        .run();
  }
}
