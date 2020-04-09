// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.security.Key;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class HMACBench {
    private static final int[] SIZES = new int[] { 16, 24, 32, 48, 64, 128, 256, 512, 1024, 2048 };

    public static void main(String[] args) throws Throwable {
        Provider np = AmazonCorrettoCryptoProvider.INSTANCE;
        for (final Service s : np.getServices()) {
            if (s.getType().equals("Mac")) {
                bench(s);
            }
        }

        for (final Provider p : Security.getProviders()) {
            for (final Service s : p.getServices()) {
                if (s.getType().equals("Mac")) {
                    bench(s);
                }
            }
        }
    }

    private static void bench(final Service s) throws Throwable {
        SecureRandom rnd = new SecureRandom();
        if (!s.getAlgorithm().startsWith("Hmac") && !s.getAlgorithm().contains("PKCS")) {
            return;
        }

        Mac mac = Mac.getInstance(s.getAlgorithm(), s.getProvider());

        byte[] key = new byte[mac.getMacLength()];
        rnd.nextBytes(key);

        Key k = new SecretKeySpec(key, s.getAlgorithm());

        for (int size : SIZES) {
            byte[] data = new byte[size];
            rnd.nextBytes(data);
            int seconds = 3;
            long endTime = System.nanoTime() + seconds * 1_000_000_000L;
            int cycles = 0;
            while (System.nanoTime() < endTime) {
                mac.reset();
                mac.init(k);
                mac.update(data);
                mac.doFinal();
                cycles++;
            }

            System.out.println(String.format("%s(%s): %d cycles of size %d in 3 seconds",
                    s.getAlgorithm(), s.getProvider().getName(), cycles, size));
        }
    }
}
