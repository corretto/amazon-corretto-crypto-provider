// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class RsaGenTest {
    private static final byte[] PLAINTEXT = new byte[32];

    @Before
    public void setUp() throws Exception {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
    }

    private KeyPairGenerator getGenerator() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("RSA", "AmazonCorrettoCryptoProvider");
    }

    @Test
    public void noInit() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test128() throws GeneralSecurityException {
        assumeMinimumVersion("1.1.0", AmazonCorrettoCryptoProvider.INSTANCE);
        final KeyPairGenerator generator = getGenerator();
        assertThrows(InvalidParameterException.class, () -> generator.initialize(128));
    }

    @Test
    public void test512() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(512);
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(512, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test512_3() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F0));
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(512, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F0, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test1024() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(1024);
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(1024, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test2048() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(2048, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test3072() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(3072);
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(3072, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void test4096() throws GeneralSecurityException {
        final KeyPairGenerator generator = getGenerator();
        generator.initialize(4096);
        final KeyPair keyPair = generator.generateKeyPair();
        final RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        final RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        assertEquals(4096, pubKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, pubKey.getPublicExponent());
        assertConsistency(pubKey, privKey);
    }

    @Test
    public void threadStorm() throws Throwable {
        final byte[] rngSeed = TestUtil.getRandomBytes(20);
        System.out.println("RNG Seed: " + Hex.toHexString(rngSeed));
        final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(rngSeed);
        final int generatorCount = 8;
        final int iterations = 250;
        final int threadCount = 48;

        final KeyPairGenerator[] generators = new KeyPairGenerator[generatorCount];
        for (int x = 0; x < generatorCount; x++) {
            generators[x] = KeyPairGenerator.getInstance("RSA", "AmazonCorrettoCryptoProvider");
            generators[x].initialize(1024);
        }

        final List<TestThread> threads = new ArrayList<>();
        for (int x = 0; x < threadCount; x++) {
            threads.add(new TestThread("RsaGenThread-" + x, iterations, generators[rng.nextInt(generatorCount)]));
        }

        // Start the threads
        for (final TestThread t : threads) {
            t.start();
        }

        // Wait and collect the results
        final List<Throwable> results = new ArrayList<>();
        for (final TestThread t : threads) {
            t.join();
            if (t.result != null) {
                results.add(t.result);
            }
        }
        if (!results.isEmpty()) {
            final AssertionError ex = new AssertionError("Throwable while testing threads");
            for (Throwable t : results) {
                ex.addSuppressed(t);
            }
            throw ex;
        }
    }

    private static void assertConsistency(final RSAPublicKey pub, final RSAPrivateCrtKey priv)
            throws GeneralSecurityException {
        assertNotNull(pub);
        assertNotNull(priv);
        assertEquals(pub.getPublicExponent(), priv.getPublicExponent());
        assertNotNull(pub.getModulus());
        assertEquals(pub.getModulus(), priv.getModulus());
        assertNotNull(priv.getPrivateExponent());
        assertNotNull(priv.getPrimeExponentP());
        assertNotNull(priv.getPrimeExponentQ());
        assertNotNull(priv.getPrimeExponentP());
        assertNotNull(priv.getPrimeExponentQ());
        assertNotNull(priv.getCrtCoefficient());

        // Do the underlying math
        assertEquals(priv.getModulus(), priv.getPrimeP().multiply(priv.getPrimeQ()));
        assertEquals(priv.getPrivateExponent().mod(priv.getPrimeP().subtract(BigInteger.ONE)), priv.getPrimeExponentP());
        assertEquals(priv.getPrivateExponent().mod(priv.getPrimeQ().subtract(BigInteger.ONE)), priv.getPrimeExponentQ());
        assertEquals(priv.getPrimeQ().modInverse(priv.getPrimeP()), priv.getCrtCoefficient());

        // Actually use the key
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        final byte[] ciphertext = cipher.doFinal(PLAINTEXT);
        cipher.init(Cipher.DECRYPT_MODE, priv);
        assertArrayEquals(PLAINTEXT, cipher.doFinal(ciphertext));
    }

    private static class TestThread extends Thread {
        private final KeyPairGenerator kg_;
        private final int iterations_;
        public volatile Throwable result = null;

        private TestThread(final String name, final int iterations, final KeyPairGenerator kg) {
            super(name);
            kg_ = kg;
            iterations_ = iterations;
        }

        @Override
        public void run() {
            for (int x = 0; x < iterations_; x++) {
                try {
                    final KeyPair keyPair = kg_.generateKeyPair();
                    assertConsistency((RSAPublicKey) keyPair.getPublic(), (RSAPrivateCrtKey) keyPair.getPrivate());
                } catch (final Throwable t) {
                    result = t;
                    return;
                }
            }
        }
    }
}
