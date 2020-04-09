// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;

import com.amazon.corretto.crypto.provider.*;

public class SecureRandomBench {
    private static final int[] SIZES = new int[] { 1, 4, 8, 16, 32, 128, 1024 };

    public static void main(String[] args) throws Exception {
        AmazonCorrettoCryptoProvider.install();
        if (args.length > 0) {
            @SuppressWarnings("unchecked")
            Class<? extends SecureRandom> clazz = (Class<? extends SecureRandom>) Class
                    .forName(args[0]);
            final SecureRandom tmp = clazz.newInstance();
            bench(tmp);
            for (int size : SIZES) {
                benchThreads(clazz, size, 128);
            }
            for (int size : SIZES) {
                benchThreads(clazz, size, 1024);
            }
        }

        for (final Provider p : Security.getProviders()) {
            for (final Service s : p.getServices()) {
                if (s.getType().equals("SecureRandom")) {
                    // Skip blocking, it is too slow
                    if (!s.getAlgorithm().equals("NativePRNGBlocking")) {
                        System.out.println("======\n" + s);
                        final SecureRandom rnd = SecureRandom.getInstance(s.getAlgorithm(), p);
                        bench(rnd);
                        for (int size : SIZES) {
                            benchThreads(s.getAlgorithm(), p, size, 128);
                        }
                        for (int size : SIZES) {
                            benchThreads(s.getAlgorithm(), p, size, 1024);
                        }
                    }
                }
            }
        }

    }

    private static void benchThreads(Class<? extends SecureRandom> clazz, final int size,
            final int threadCnt) throws InstantiationException, IllegalAccessException,
            InterruptedException {
        if (size < 16) {
            return;
        }
        TestThread[] threads = new TestThread[threadCnt];
        for (int x = 0; x < threads.length; x++) {
            threads[x] = new TestThread(clazz.newInstance(), size, 256 * 1024 * 1024 / size
                    / threadCnt);
        }
        long start = System.nanoTime();
        for (int x = 0; x < threads.length; x++) {
            threads[x].start();
        }
        for (int x = 0; x < threads.length; x++) {
            threads[x].join();
        }
        long stop = System.nanoTime();
        System.out.println(String.format("%s: %d threads in increments of %d (256MB):\t%dms", clazz
                .newInstance().getAlgorithm(), threadCnt, size, ((stop - start) / 1_000_000L)));
    }

    private static void benchThreads(String alg, Provider p, final int size, final int threadCnt)
            throws InstantiationException, IllegalAccessException, InterruptedException,
            NoSuchAlgorithmException {
        if (size < 16) {
            return;
        }
        TestThread[] threads = new TestThread[threadCnt];
        for (int x = 0; x < threads.length; x++) {
            threads[x] = new TestThread(SecureRandom.getInstance(alg, p), size, 256 * 1024 * 1024
                    / size / threadCnt);
        }
        long start = System.nanoTime();
        for (int x = 0; x < threads.length; x++) {
            threads[x].start();
        }
        for (int x = 0; x < threads.length; x++) {
            threads[x].join();
        }
        long stop = System.nanoTime();
        System.out.println(String.format("%s: %d threads in increments of %d (256MB):\t%dms",
                SecureRandom.getInstance(alg, p).getAlgorithm(), threadCnt, size,
                ((stop - start) / 1_000_000L)));
    }

    private static void bench(final SecureRandom rnd) {

        for (int size : SIZES) {
            final int steps = 1024 * 1024 / size;
            byte accum = 0;
            final byte[] buff = new byte[size];
            final long start = System.nanoTime();
            for (int x = 0; x < steps; x++) {
                rnd.nextBytes(buff);
                accum = (byte) (accum ^ buff[0]);
            }
            final long stop = System.nanoTime();
            System.out.println(String.format("%s: 1MB in increments of %d:\t%dms",
                    rnd.getAlgorithm(), size, ((stop - start) / 1_000_000L)));
        }
    }

    private static class TestThread extends Thread {
        private final SecureRandom rnd_;
        private final byte[] buff_;
        private final int iterations_;

        public TestThread(final SecureRandom rnd, final int size, final int iterations) {
            rnd_ = rnd;
            buff_ = new byte[size];
            iterations_ = iterations;
        }

        @Override
        public void run() {
            byte accum = 0;
            for (int x = 0; x < iterations_; x++) {
                rnd_.nextBytes(buff_);
                accum = (byte) (accum ^ buff_[0]);
            }
        }
    }
}
