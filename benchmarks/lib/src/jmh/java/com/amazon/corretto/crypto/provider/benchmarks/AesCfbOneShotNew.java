// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class AesCfbOneShotNew {
    private static final int BLOCK_SIZE = 16;

    @Param({"128", "256"})
    public int keyBits;

    @Param({"16", "64", "256", "1024", "4096", "16384"})
    public int dataSize;

    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
    public String provider;

    private SecretKeySpec key;
    private IvParameterSpec iv;
    private Cipher encryptor;
    private Cipher decryptor;
    private byte[] plaintext;
    private byte[] ciphertext;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        
        // Generate key
        key = new SecretKeySpec(BenchmarkUtils.getRandBytes(keyBits / 8), "AES");
        
        // Generate IV
        iv = new IvParameterSpec(BenchmarkUtils.getRandBytes(BLOCK_SIZE));
        
        // Generate plaintext
        plaintext = BenchmarkUtils.getRandBytes(dataSize);
        
        // Setup ciphers
        final String algorithm = "AES/CFB/NoPadding";
        encryptor = Cipher.getInstance(algorithm, provider);
        decryptor = Cipher.getInstance(algorithm, provider);
        
        // Generate ciphertext for decryption benchmark
        encryptor.init(Cipher.ENCRYPT_MODE, key, iv);
        ciphertext = encryptor.doFinal(plaintext);
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        encryptor.init(Cipher.ENCRYPT_MODE, key, iv);
        return encryptor.doFinal(plaintext);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        decryptor.init(Cipher.DECRYPT_MODE, key, iv);
        return decryptor.doFinal(ciphertext);
    }
}