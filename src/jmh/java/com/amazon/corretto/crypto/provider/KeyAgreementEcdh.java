package com.amazon.corretto.crypto.provider;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Setup;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


@State(Scope.Benchmark)
public class KeyAgreementEcdh {

    @Param({ "secp256r1", "secp384r1", "secp521r1" })
    public String curve;

    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SunEC" })
    public String provider;

    protected KeyPair alice;
    protected KeyPair bob;
    protected KeyAgreement keyAgreement;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECGenParameterSpec(curve));
        alice = kpg.generateKeyPair();
        bob = kpg.generateKeyPair();
        keyAgreement = KeyAgreement.getInstance("ECDH", provider);
    }

    @Benchmark
    public byte[] agree() throws Exception {
        keyAgreement.init(alice.getPrivate());
        keyAgreement.doPhase(bob.getPublic(), /*lastPhase*/true);
        return keyAgreement.generateSecret();
    }
}
