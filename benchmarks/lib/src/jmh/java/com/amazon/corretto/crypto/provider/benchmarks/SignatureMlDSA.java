// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class SignatureMlDSA extends SignatureBase {
    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC"})
    public String provider;

    @Param({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public String algo;

    @Setup
    public void setup() throws Exception {
        super.setup(provider, algo, null, "ML-DSA", null);
    }

    @Benchmark
    public byte[] sign() throws Exception {
        return super.sign();
    }

    @Benchmark
    public boolean verify() throws Exception {
        return super.verify();
    }
}
