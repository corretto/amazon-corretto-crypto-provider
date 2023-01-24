// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

public class SmallHashBench {
    public static void main(String[] args) throws Throwable {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);

        for (Provider p : Security.getProviders()) {
            if (null != p.get("MessageDigest.SHA-256")) {
                benchNewInstance(p, 1);
                benchReuseInstance(p, 1);
            }
        }

        System.out.println("=== Round 2 ===");

        for (Provider p : Security.getProviders()) {
            if (null != p.get("MessageDigest.SHA-256")) {
                benchNewInstance(p, 10);
                benchReuseInstance(p, 10);
            }
        }
    }

    private static void benchNewInstance(Provider provider, int seconds) throws Exception {
        byte[] data = new byte[8];

        new SecureRandom().nextBytes(data);

        long endTime = System.nanoTime() + seconds * 1_000_000_000L;
        int cycles = 0;
        while (System.nanoTime() < endTime) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256", provider);
            digest.digest(data);
            cycles++;
        }

        System.out.println("" + cycles + " hashes in " + seconds + " seconds for provider " + provider.getName() + " (new instances)");
    }


    private static void benchReuseInstance(Provider provider, int seconds) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256", provider);
        byte[] data = new byte[8];

        new SecureRandom().nextBytes(data);

        long endTime = System.nanoTime() + seconds * 1_000_000_000L;
        int cycles = 0;
        while (System.nanoTime() < endTime) {
            digest.digest(data);
            cycles++;
        }

        System.out.println("" + cycles + " hashes in " + seconds + " seconds for provider " + provider.getName() + " (reused instances)");
    }
}
