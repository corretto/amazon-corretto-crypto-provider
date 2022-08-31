package com.amazon.corretto.crypto.provider;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.infra.Blackhole;

import java.security.Provider;
import java.security.Security;
import java.security.Key;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


@State(Scope.Benchmark)
public class Hmac {
    @Param({ "SHA256" })
    public String hash;

    @Param({ "1024", "65536" })
    public int size;

    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunJCE" })
    public String provider;

    protected Key key;
    private byte[] data;
    private Mac mac;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        final String algorithm = "Hmac" + hash;
        data = BenchmarkUtils.getRandBytes(size);
        mac = Mac.getInstance(algorithm, provider);
        key = new SecretKeySpec(BenchmarkUtils.getRandBytes(mac.getMacLength()), algorithm);
        mac.init(key);
    }

    @Benchmark
    public byte[] oneShot() {
        return mac.doFinal(data);
    }
}

