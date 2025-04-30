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

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
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

@State(Scope.Benchmark)
public class AesCfbOneShot extends AesCfbBase {
    @Param({"128", "256"})
    public int keyBits;

    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE"})
    public String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(keyBits, provider);
    }

    @Benchmark
    public byte[] oneShot1MiBEncrypt() throws Exception {
        encryptor.init(Cipher.ENCRYPT_MODE, key, params1);
        byte[] out = encryptor.doFinal(plaintext);
        encryptor.init(Cipher.ENCRYPT_MODE, key, params2);
        return out;
    }

    @Benchmark
    public byte[] oneShot1MiBDecrypt() throws Exception {
        decryptor.init(Cipher.DECRYPT_MODE, key, params1);
        byte[] out = decryptor.doFinal(ciphertext);
        decryptor.init(Cipher.DECRYPT_MODE, key, params2);
        return out;
    }
}