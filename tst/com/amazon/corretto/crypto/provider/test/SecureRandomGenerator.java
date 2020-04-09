// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;
import java.util.function.Function;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

@SuppressWarnings("overloads")
public class SecureRandomGenerator {
    public static void main(final String[] args) throws GeneralSecurityException, IOException {
        AmazonCorrettoCryptoProvider.install();
        if (args.length < 3) {
            printUsage();
            return;
        }
        boolean useSeed = false;
        if (args.length > 3) {
            if ("--seed".equals(args[3])) {
                System.err.println("Using generateSeed()");
                useSeed = true;
            } else {
                printUsage();
                return;
            }
        }
        final String algorithm = args[0];
        final int chunkSize = Integer.parseInt(args[1]);
        final int threads = Integer.parseInt(args[2]);

        final ArrayBlockingQueue<byte[]> queue = new ArrayBlockingQueue<>(threads * 4);
        final ThrowingSupplier coreGetRandom;

        switch (algorithm) {
          case "--rdrand":
            if (useSeed) {
              printUsage();
              return;
            }
            coreGetRandom = convert(NativeTestHooks::rdrand, chunkSize);
            break;

          case "--rdseed":
            if (useSeed) {
              printUsage();
              return;
            }
            if (!NativeTestHooks.hasRdseed()) {
              throw new RuntimeException("RDSEED not supported");
            }
            coreGetRandom = convert(NativeTestHooks::rdseed, chunkSize);
            break;

          default:
            final SecureRandom rnd = SecureRandom.getInstance(algorithm);
            if (useSeed) {
              coreGetRandom = () -> rnd.generateSeed(chunkSize);
            } else {
              coreGetRandom = convert((Consumer<byte[]>)rnd::nextBytes, chunkSize);
            }
        }


        final ThrowingSupplier getRandom;
        if (threads == 1) {
            getRandom = coreGetRandom;
        } else {
            CountDownLatch latch = new CountDownLatch(threads);
            for (int t = 0; t < threads; t++) {
                SupplierThread st = new SupplierThread(coreGetRandom, queue, latch);
                st.setDaemon(true);
                st.setName("SecureRandom-" + t);
                st.start();
            }
            getRandom = queue::take;
        }

        while (!System.out.checkError()) {
            try {
                System.out.write(getRandom.get());
            } catch (final InterruptedException ex) {
                // Ignore this
            }
        }
    }

    private static void printUsage() {
        System.out.println("CMD <algorithm|--rdseed|--rdrand> <chunk size> <thread count> [--seed]");
        System.out.println("\t--seed must not be used with --rdseed or --rdrand");
        System.out.println();
        System.out.println("Algorithms:");
        for (final Provider p : Security.getProviders()) {
            for (final Service s : p.getServices()) {
                if (s.getType().equals("SecureRandom")) {
                    System.out.println(s.getAlgorithm());
                }
            }
        }
    }

    private static ThrowingSupplier convert(Function<byte[], Boolean> delegate, int size) {
      return () -> {
        final byte[] buffer = new byte[size];
        if (!delegate.apply(buffer)) {
          throw new RuntimeException("Call to delegate failed");
        }
        return buffer;
      };
    }

    private static ThrowingSupplier convert(Consumer<byte[]> delegate, final int size) {
      return () -> {
        final byte[] buffer = new byte[size];
        delegate.accept(buffer);
        return buffer;
      };
    }

    @FunctionalInterface
    private interface ThrowingSupplier {
        byte[] get() throws InterruptedException;
    }

    private static final class SupplierThread extends Thread {
        private final ThrowingSupplier supplier;
        private final CountDownLatch latch;
        private final ArrayBlockingQueue<byte[]> queue;

        public SupplierThread(ThrowingSupplier supplier, ArrayBlockingQueue<byte[]> queue, CountDownLatch latch) {
            this.supplier = supplier;
            this.queue = queue;
            this.latch = latch;
        }

        @Override
        public void run() {
            try {
                latch.countDown();
                latch.await();
                while(true) {
                    queue.put(supplier.get());
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
