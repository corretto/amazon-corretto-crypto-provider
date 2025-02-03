package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

@State(Scope.Thread)
public class CipherReuse {
    private final static String AES = "AES";
    private final static String AES_GCM = "AES/GCM/NoPadding";
    Cipher shared;
    SecretKeySpec key;
    Random random = new Random();
    byte[] iv = new byte[12];
    byte[] input = new byte[1000];
    byte[] keyb = new byte[32];
    byte[] aad = new byte[100];

    @Param({"true", "false"})
    private boolean newKey;

    @Setup
    public void setup() throws Exception {
        shared = getAesGcmCipherFromAccp();
        random.nextBytes(keyb);
        key = new SecretKeySpec(keyb, AES);
        random.nextBytes(input);
        random.nextBytes(aad);
    }

    @Benchmark
    public void newInstance(Blackhole blackhole) throws Exception {
        blackhole.consume(encryptDecrypt(getAesGcmCipherFromAccp()));
    }

    @Benchmark
    public void reuse(Blackhole blackhole) throws Exception {
        blackhole.consume(encryptDecrypt(shared));
    }

    byte[] encryptDecrypt(final Cipher cipher) throws Exception {
        iv[0]++;
        final SecretKey sk;
        if (newKey) {
            keyb[0]++;
            sk = new SecretKeySpec(keyb, AES);
        } else {
            sk = key;
        }
        cipher.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        final byte[] cipherText = cipher.doFinal(input);
        cipher.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(cipherText);
    }

    private Cipher getAesGcmCipherFromAccp() {
        try {
            return Cipher.getInstance(AES_GCM, AmazonCorrettoCryptoProvider.INSTANCE);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
