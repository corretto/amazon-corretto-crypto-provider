// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class MLKEMEncapDecap {
    @Param({ "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
    public String algorithm;

    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC" })
    public String provider;

    private KEM kem;
    private KeyPair keyPair;
    private AlgorithmParameterSpec paramSpec;
    private byte[] ciphertext;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
        keyPair = kpg.generateKeyPair();

        // BC uses generic "ML-KEM" to get a KEM instance while ACCP uses specific parameter set (e.g "ML-KEM-512")
        String algorithmName = "BC".equals(provider) ? "ML-KEM" : algorithm;
        kem = KEM.getInstance(algorithmName, provider);

        if ("BC".equals(provider)) {
            paramSpec = new KTSParameterSpec.Builder(algorithm, 256).build();
        } else {
            paramSpec = new NamedParameterSpec(algorithm);
        }
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic(), paramSpec, null);
        KEM.Encapsulated result = encapsulator.encapsulate();
        ciphertext = result.encapsulation();
    }

    @Benchmark
    public KEM.Encapsulated encapsulate() throws Exception {
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic(), paramSpec, null);
        return encapsulator.encapsulate();
    }

    @Benchmark
    public SecretKey decapsulate() throws Exception {
        KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate(), paramSpec);
        return decapsulator.decapsulate(ciphertext);
    }
}
