// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.net.URL;
import java.net.URLClassLoader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 1)
@State(Scope.Benchmark)
public class AesCfbOneShot {
    private static final String ALGORITHM = "AES/CFB/NoPadding";
    private static final int BLOCK_SIZE = 16;

    @Param({"128", "256"})
    private int keySize;

    @Param({"16", "64", "256", "1024", "4096", "16384"})
    private int dataSize;

    @Param({"SunJCE", "AmazonCorrettoCryptoProvider", "BC"})
    private String providerName;

    private Provider provider;
    private SecretKey key;
    private IvParameterSpec iv;
    private byte[] plaintext;
    private byte[] ciphertext;

    @Setup(Level.Trial)
    public void setupProvider() throws Exception {
        if ("AmazonCorrettoCryptoProvider".equals(providerName)) {
            provider = Security.getProvider("AmazonCorrettoCryptoProvider");
            if (provider == null) {
                try {
                    // Try to load from the JAR in resources
                    URL jarUrl = getClass().getClassLoader().getResource("AmazonCorrettoCryptoProvider.jar");
                    if (jarUrl != null) {
                        URLClassLoader classLoader = new URLClassLoader(new URL[]{jarUrl}, getClass().getClassLoader());
                        Class<?> providerClass = classLoader.loadClass("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
                        provider = (Provider) providerClass.getField("INSTANCE").get(null);
                        Security.insertProviderAt(provider, 1);
                        System.out.println("Loaded AmazonCorrettoCryptoProvider from resources JAR");
                    } else {
                        // Fall back to the standard way
                        provider = (Provider) Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider")
                                .getField("INSTANCE").get(null);
                        Security.insertProviderAt(provider, 1);
                        System.out.println("Loaded AmazonCorrettoCryptoProvider from classpath");
                    }
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException("Unable to load AmazonCorrettoCryptoProvider", e);
                }
            }
        } else if ("BC".equals(providerName)) {
            provider = Security.getProvider("BC");
            if (provider == null) {
                try {
                    // Load BouncyCastle provider
                    provider = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
                    Security.insertProviderAt(provider, 1);
                    System.out.println("Loaded BouncyCastle provider");
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException("Unable to load BouncyCastle provider", e);
                }
            }
        } else {
            provider = Security.getProvider(providerName);
        }
        
        if (provider == null) {
            throw new RuntimeException("Provider not found: " + providerName);
        }
    }

    @Setup(Level.Iteration)
    public void setup() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(keySize);
        key = keyGen.generateKey();
        
        // Generate IV
        byte[] ivBytes = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
        
        // Generate plaintext
        plaintext = new byte[dataSize];
        new SecureRandom().nextBytes(plaintext);
        
        // Generate ciphertext for decryption benchmark
        Cipher encryptCipher = Cipher.getInstance(ALGORITHM, provider);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        ciphertext = encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public void encrypt(Blackhole blackhole) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] result = cipher.doFinal(plaintext);
        blackhole.consume(result);
    }

    @Benchmark
    public void decrypt(Blackhole blackhole) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, provider);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] result = cipher.doFinal(ciphertext);
        blackhole.consume(result);
    }
}