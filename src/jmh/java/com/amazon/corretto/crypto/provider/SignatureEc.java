package com.amazon.corretto.crypto.provider;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Setup;

import java.security.spec.ECGenParameterSpec;


@State(Scope.Benchmark)
public class SignatureEc extends SignatureBase {
    @Param({ "SHA1" })
    public String hash;

    @Param({ "secp256r1", "secp384r1", "secp521r1" })
    public String curve;

    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunEC" })
    public String provider;

    @Setup
    public void setup() throws Exception {
        super.setup(provider, "EC", new ECGenParameterSpec(curve), String.format("%swithECDSA", hash), null);
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
