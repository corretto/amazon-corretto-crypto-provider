// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.text.NumberFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class AESBench {
    public static void main(String[] args) throws Throwable {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);

        byte[] rawKey = TestUtil.getRandomBytes(16);
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        Cipher jce = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher amzn = Cipher.getInstance("AES/GCM/NoPadding", "AmazonCorrettoCryptoProvider");

        // Warm JIT
        runBench(jce, key, 10, 16);
        runBench(amzn, key, 10, 16);

        bench(jce, key);
        bench(amzn, key);

        rawKey = TestUtil.getRandomBytes(32);
        key = new SecretKeySpec(rawKey, "AES");
        bench(jce, key);
        bench(amzn, key);
    }

    private static void bench(Cipher cipher, Key key) throws GeneralSecurityException {
        int[] sizes = new int[] { 16, 64, 256, 1024, 8192, 16384, 32768, 65536 };

        final int seconds = 3;

        for (int size : sizes) {
            runBench(cipher, key, seconds, size);
        }

    }

    private static void runBench(Cipher cipher, Key key, int seconds, int size) throws InvalidKeyException,
        InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = TestUtil.getRandomBytes(12);

        NumberFormat fmt = NumberFormat.getIntegerInstance();
        fmt.setGroupingUsed(true);

        byte[] ciphertext = new byte[0];
        byte[] data = TestUtil.getRandomBytes(size);
        long encCycles = 0;

        long startTime = System.nanoTime();
        long endTime = startTime + seconds * 1_000_000_000L;
        while (System.nanoTime() < endTime) {
            iv[0] ^= 0xFF;
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            ciphertext = cipher.doFinal(data);
            encCycles++;
        }
        long encElapsed = endTime - startTime;

        long decCycles = 0;
        startTime = System.nanoTime();
        endTime = startTime + seconds * 1_000_000_000L;
        while (System.nanoTime() < endTime) {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            cipher.doFinal(ciphertext);
            decCycles++;
        }
        long decElapsed = endTime - startTime;

        System.out.println(
            String.format(
                "Doing aes-%d-gcm(%s) for %ds seconds on %d size buffers (encrypt/decrypt): %s/%s operations - throughput %3.2f/%3.2f MB/s",
                key.getEncoded().length * 8,
                cipher.getProvider().getName(),
                seconds,
                size,
                fmt.format(encCycles),
                fmt.format(decCycles),
                size * encCycles / (1024.0*1024) / (encElapsed / 1_000_000_000.0),
                size * decCycles / (1024.0*1024) / (decElapsed / 1_000_000_000.0)
            )
        );
    }
}
