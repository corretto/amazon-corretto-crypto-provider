package com.amazon.corretto.crypto.provider;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.infra.Blackhole;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


@State(Scope.Benchmark)
public class Hashes {
    @Param({ "SHA-1", "SHA-256", "SHA-384" })
    public String algorithm;

    @Param({ "8", "1024", "65536" })
    public int size;

    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SUN" })
    public String provider;

    private byte[] data;
    private MessageDigest digest;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        data = BenchmarkUtils.getRandBytes(size);
        digest = MessageDigest.getInstance(algorithm, provider);
    }

    @Benchmark
    public byte[] oneShot() {
        return digest.digest(data);
    }
}

