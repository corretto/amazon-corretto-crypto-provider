// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static java.lang.String.format;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class Benchmark {
    public static void main(String[] args) throws Throwable {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
        benchHashes();
        benchEcGen();
        benchRsaGen();
        benchRsa();
        benchNonEcSignatures();
        benchEcSignatures();
        AESBench.main(args);
    }

    private static void benchNonEcSignatures() throws GeneralSecurityException {
        final List<String> bases = Arrays.asList("DSA", "RSA");
        final List<String> hashes = Arrays.asList("SHA1", "SHA224", "SHA256", "SHA384", "SHA512");

        for (final String base : bases) {
            for (final String hash : hashes) {
                final String algorithm = format("%swith%s", hash, base);
                for (int keySize : new int[] { 2048, 3072, 4096 }) {
                    for (Provider p : Security.getProviders()) {
                        try {
                            final KeyPairGenerator kg = KeyPairGenerator.getInstance(base);
                            kg.initialize(keySize);
                            final KeyPair keyPair = kg.generateKeyPair();
                            if (p.getService("Signature", algorithm) != null) {
                                bench(keySize, Signature.getInstance(algorithm, p), keyPair);
                            }
                        } catch (InvalidParameterException ex) {
                            // Not all algorithms support all key sizes.
                        }
                    }
                }
            }
        }
    }

    private static void benchEcSignatures() throws GeneralSecurityException {
        final List<String> hashes = Arrays.asList("SHA1", "SHA224", "SHA256", "SHA384", "SHA512");
            for (final String hash : hashes) {
                final String algorithm = format("%swithECDSA", hash);
                for (String curve : new String[] { "secp192k1", "secp256k1", "secp384r1", "secp521r1" }) {
                    for (Provider p : Security.getProviders()) {
                        final KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
                        kg.initialize(new ECGenParameterSpec(curve));
                        final KeyPair keyPair = kg.generateKeyPair();
                        if (p.getService("Signature", algorithm) != null) {
                            bench(curve, Signature.getInstance(algorithm, p), keyPair);
                        }
                    }
                }
            }
    }

    private static void benchHashes() throws NoSuchAlgorithmException {
        int[] sizes = new int[] { 16, 32, 64, 128, 512, 1024, 4096, 8192, 16384, 65536 };

        for (String hashFunction : new String[] { "MD5", "SHA-1", "SHA-256" }) {
            for (Provider p : Security.getProviders()) {
                for (int size : sizes) {
                    if (p.getService("MessageDigest", hashFunction) != null) {
                        bench(size, MessageDigest.getInstance(hashFunction, p));
                    }
                }
            }
        }
    }

    private static void benchEcGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final String[] curves = new String[]{"secp112r1", "secp128r1", "secp160r1", "secp192k1",
                "secp224r1", "secp256k1", "secp384r1", "secp521r1"};

        for (Provider p : Security.getProviders()) {
            for (String name : curves) {
                if (p.getService("KeyPairGenerator", "EC") != null) {
                    bench(new ECGenParameterSpec(name), name, KeyPairGenerator.getInstance("EC", p));
                }
            }
        }
    }

    private static void benchRsaGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final int[] sizes = new int[] { 2048, 3072, 4096 };

        for (Provider p : Security.getProviders()) {
            for (int size : sizes) {
                if (p.getService("KeyPairGenerator", "RSA") != null) {
                    bench(new RSAKeyGenParameterSpec(size, RSAKeyGenParameterSpec.F4), size, KeyPairGenerator.getInstance("RSA", p));
                }
            }
        }
    }

    private static void benchRsa() throws GeneralSecurityException {
        final int seconds = 3;
        final int[] sizes = new int[] { 2048, 3072, 4096 };
        Map<Integer, KeyPair> keys = new HashMap<Integer, KeyPair>();
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        for (int size : sizes) {
            kg.initialize(size);
            keys.put(size, kg.generateKeyPair());
        }

        for (Provider p : Security.getProviders()) {
            for (int size : sizes) {
                final KeyPair keyPair = keys.get(size);
                try {
                    byte[] message = new byte[size / 8];
                    Arrays.fill(message, (byte) 0x5);
                    final Cipher enc = Cipher.getInstance("RSA/ECB/NoPadding", p);
                    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                    final Cipher dec = Cipher.getInstance("RSA/ECB/NoPadding", p);
                    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

                    long endTime = System.nanoTime() + seconds * 1_000_000_000L;
                    int cycles = 0;
                    while (System.nanoTime() < endTime) {
                        dec.doFinal(enc.doFinal(message));
                        cycles++;
                    }

                    System.out.println("" + cycles + " enc/dec cycles in " + seconds + " seconds for size " + size
                            + ", algorithm "
                            + enc.getAlgorithm() + ", provider " + p.getName());
                } catch (final GeneralSecurityException ex) {
                    // Purposefully ignore
                }

                try {
                    byte[] message = new byte[(size / 8) - 11];
                    Arrays.fill(message, (byte) 0x5);
                    final Cipher enc = Cipher.getInstance("RSA/ECB/Pkcs1Padding", p);
                    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                    final Cipher dec = Cipher.getInstance("RSA/ECB/Pkcs1Padding", p);
                    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

                    long endTime = System.nanoTime() + seconds * 1_000_000_000L;
                    int cycles = 0;
                    while (System.nanoTime() < endTime) {
                        dec.doFinal(enc.doFinal(message));
                        cycles++;
                    }

                    System.out.println("" + cycles + " enc/dec cycles in " + seconds + " seconds for size " + size
                            + ", algorithm "
                            + enc.getAlgorithm() + ", provider " + p.getName());
                } catch (final GeneralSecurityException ex) {
                    // Purposefully ignore
                }

                try {
                    byte[] message = new byte[(size / 8) - 64];
                    Arrays.fill(message, (byte) 0x5);
                    final Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", p);
                    enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                    final Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", p);
                    dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

                    long endTime = System.nanoTime() + seconds * 1_000_000_000L;
                    int cycles = 0;
                    while (System.nanoTime() < endTime) {
                        dec.doFinal(enc.doFinal(message));
                        cycles++;
                    }

                    System.out.println("" + cycles + " enc/dec cycles in " + seconds + " seconds for size " + size
                            + ", algorithm "
                            + enc.getAlgorithm() + ", provider " + p.getName());
                } catch (final GeneralSecurityException ex) {
                    // Purposefully ignore
                }
            }
        }
    }

    private static void bench(Object size, Signature instance, KeyPair keyPair) throws GeneralSecurityException {
        byte[] data = new byte[1024];

        new SecureRandom().nextBytes(data);

        int seconds = 3;
        long endTime = System.nanoTime() + seconds * 1_000_000_000L;
        int cycles = 0;
        int tmp = 0;
        byte[] signature = null;
        try {
            while (System.nanoTime() < endTime) {
                instance.initSign(keyPair.getPrivate());
                instance.update(data);
                signature = instance.sign();
                tmp += signature.length;
                cycles++;
            }

            System.out.println("" + cycles + " signatures in " + seconds + " seconds for key-type " + size + ", algorithm "
                    + instance.getAlgorithm() + ", provider " + instance.getProvider().getName());

            endTime = System.nanoTime() + seconds * 1_000_000_000L;
            cycles = 0;
            tmp = 0;
            while (System.nanoTime() < endTime) {
                instance.initVerify(keyPair.getPublic());
                instance.update(data);
                tmp += instance.verify(signature) ? 1 : 0;
                cycles++;
            }
            if (tmp == 0) {
                throw new RuntimeException("Force read of tmp to avoid optimizing out");
            }
        } catch (final InvalidKeyException ex) {
            // There are some invalid cominations we try to test simply because it is easier than
            // avoiding them.
            System.err.println("Not testing due to exception");
            ex.printStackTrace();
        }

        System.out.println("" + cycles + " verifications in " + seconds + " seconds for key-type " + size
                + ", algorithm " + instance.getAlgorithm() + ", provider " + instance.getProvider().getName());
    }

    private static void bench(int size, MessageDigest instance) {
        byte[] data = new byte[size];

        new SecureRandom().nextBytes(data);

        int seconds = 3;
        long endTime = System.nanoTime() + seconds * 1_000_000_000L;
        int cycles = 0;
        while (System.nanoTime() < endTime) {
            instance.digest(data);
            cycles++;
        }

        System.out.println("" + cycles + " blocks in " + seconds + " seconds for size " + size + ", algorithm "
                + instance.getAlgorithm() + ", provider " + instance.getProvider().getName());
    }

    private static void bench(AlgorithmParameterSpec spec, Object message, KeyPairGenerator instance) throws InvalidAlgorithmParameterException {
        instance.initialize(spec);

        int seconds = 10;
        long endTime = System.nanoTime() + seconds * 1_000_000_000L;
        int cycles = 0;
        while (System.nanoTime() < endTime) {
            instance.generateKeyPair();
            cycles++;
        }

        System.out.println("" + cycles + " keys generated in " + seconds + " seconds for spec " + message + ", algorithm "
                + instance.getAlgorithm() + ", provider " + instance.getProvider().getName());
    }
}
