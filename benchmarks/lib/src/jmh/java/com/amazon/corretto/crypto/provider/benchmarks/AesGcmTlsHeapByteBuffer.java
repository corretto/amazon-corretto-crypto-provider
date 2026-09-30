// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/** Models the heap-buffer, exact-in-place AES-GCM operation used by Kafka's TLS record layer. */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class AesGcmTlsHeapByteBuffer {
  private static final int TAG_LENGTH = 16;
  private static final byte[] TLS_RECORD_AAD = new byte[5];

  @Param({"1024", "16384"})
  public int recordSize;

  @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "SunJCE"})
  public String provider;

  private Key key;
  private byte[] iv;
  private byte[] plaintext;
  private byte[] ciphertext;
  private Cipher encryptor;
  private Cipher decryptor;
  private ByteBuffer encryptionRecord;
  private ByteBuffer decryptionRecord;

  @Setup(Level.Trial)
  public void setupTrial() throws Exception {
    BenchmarkUtils.setupProvider(provider);
    key = new SecretKeySpec(BenchmarkUtils.getRandBytes(16), "AES");
    iv = BenchmarkUtils.getRandBytes(12);
    plaintext = BenchmarkUtils.getRandBytes(recordSize);
    encryptor = Cipher.getInstance("AES/GCM/NoPadding", provider);
    decryptor = Cipher.getInstance("AES/GCM/NoPadding", provider);

    final Cipher ciphertextGenerator = Cipher.getInstance("AES/GCM/NoPadding", provider);
    final GCMParameterSpec parameters = new GCMParameterSpec(128, iv);
    ciphertextGenerator.init(Cipher.ENCRYPT_MODE, key, parameters);
    ciphertextGenerator.updateAAD(TLS_RECORD_AAD);
    ciphertext = ciphertextGenerator.doFinal(plaintext);

    // Kafka's SslTransportLayer creates all three SSLEngine buffers with ByteBuffer.allocate.
    encryptionRecord = ByteBuffer.allocate(recordSize + TAG_LENGTH);
    decryptionRecord = ByteBuffer.allocate(recordSize + TAG_LENGTH);
  }

  @Setup(Level.Invocation)
  public void resetRecords() {
    encryptionRecord.clear();
    encryptionRecord.put(plaintext);
    encryptionRecord.clear();

    decryptionRecord.clear();
    decryptionRecord.put(ciphertext);
    decryptionRecord.clear();
  }

  @Benchmark
  public int encryptTlsRecordInPlace() throws Exception {
    incrementIv();
    encryptor.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    encryptor.updateAAD(TLS_RECORD_AAD);

    final ByteBuffer input = encryptionRecord.duplicate();
    input.limit(recordSize);
    encryptionRecord.position(0);
    encryptionRecord.limit(recordSize + TAG_LENGTH);
    return encryptor.doFinal(input, encryptionRecord);
  }

  @Benchmark
  public int decryptTlsRecordInPlace() throws Exception {
    decryptor.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    decryptor.updateAAD(TLS_RECORD_AAD);

    final ByteBuffer input = decryptionRecord.duplicate();
    input.limit(recordSize + TAG_LENGTH);
    decryptionRecord.position(0);
    decryptionRecord.limit(recordSize);
    return decryptor.doFinal(input, decryptionRecord);
  }

  private void incrementIv() {
    for (int i = iv.length - 1; i >= 0; i--) {
      iv[i]++;
      if (iv[i] != 0) {
        return;
      }
    }
  }
}
