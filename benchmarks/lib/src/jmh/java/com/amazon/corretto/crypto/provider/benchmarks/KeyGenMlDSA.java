// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class KeyGenMlDSA {

    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC"})
    public String provider;

    @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public String algo;

    private KeyPairGenerator kpg;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        kpg = KeyPairGenerator.getInstance(algo, provider);
    }

    @Benchmark
    public KeyPair generate() {
        return kpg.generateKeyPair();
    }
}
