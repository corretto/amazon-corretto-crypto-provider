// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Threads;

@State(Scope.Benchmark)
public class SignatureEd extends SignatureBase {
    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunEC"})
    public String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(provider, "Ed25519", null, "Ed25519", null);
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