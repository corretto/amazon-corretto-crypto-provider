package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

@State(Scope.Benchmark)
public class AesGcmVsKwp {
    private static final int KEY_LEN_SIZE_IN_BITS = 256;
    @Param({"AES/GCM/NoPadding", "AES/KWP/NoPadding"})
    public String algorithm;
    protected Key kek;
    protected Key plainKey;
    protected Cipher cipher;
    protected SecureRandom srand;
    protected GCMParameterSpec gcmSpec;
    protected byte[] wrappedKeyGcm;
    protected byte[] wrappedKeyKwp;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME);

        kek = new SecretKeySpec(BenchmarkUtils.getRandBytes(KEY_LEN_SIZE_IN_BITS / 8), "AES");
        plainKey = new SecretKeySpec(BenchmarkUtils.getRandBytes(KEY_LEN_SIZE_IN_BITS / 8), "AES");
        srand = new SecureRandom();

        cipher = Cipher.getInstance(algorithm, AmazonCorrettoCryptoProvider.PROVIDER_NAME);

        final byte[] iv = new byte[16];
        srand.nextBytes(iv);
        gcmSpec = new GCMParameterSpec(128, iv);
        final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.WRAP_MODE, kek, gcmSpec);
        wrappedKeyGcm = gcm.wrap(plainKey);

        final Cipher kwp = Cipher.getInstance("AES/KWP/NoPadding");
        kwp.init(Cipher.WRAP_MODE, kek);
        wrappedKeyKwp = kwp.wrap(plainKey);
    }

    @Benchmark
    public byte[] wrap() throws Exception {
        if (algorithm.equals("AES/GCM/NoPadding")) {
            final byte[] iv = new byte[16];
            srand.nextBytes(iv);
            cipher.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, iv));
        } else {
            cipher.init(Cipher.WRAP_MODE, kek);
        }
        return cipher.wrap(plainKey);
    }

    @Benchmark
    public Key unwrap() throws Exception {
        final byte[] wrappedKey;
        if (algorithm.equals("AES/GCM/NoPadding")) {
            wrappedKey = wrappedKeyGcm;
            cipher.init(Cipher.UNWRAP_MODE, kek, gcmSpec);
        } else {
            wrappedKey = wrappedKeyKwp;
            cipher.init(Cipher.UNWRAP_MODE, kek);
        }
        return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
}
