// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static java.util.logging.Logger.getLogger;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Arrays;
import java.util.Scanner;

public class AesCtrDrbg extends SecureRandom {
    private static final String ALGORITHM_NAME = "NIST800-90A/AES-CTR-256";
    private static final long serialVersionUID = 1L;
    private static final int SEED_SIZE = 48;
    private static final int MAX_SINGLE_REQUEST = 8192;

    private static native long instantiate(byte[] seed, byte[] fakeData);

    private static native void reseed(long ptr, byte[] seed);

    private static native void generate(long ptr, byte[] bytes, int offset, int length);

    private static native void releaseState(long ptr);

    public AesCtrDrbg() {
        super(new SPI(), AmazonCorrettoCryptoProvider.INSTANCE);
    }

    /**
     * This constructor exists for testing purposes only and must remain private
     */
    private AesCtrDrbg(byte[] fakeData, byte[] seed) {
        super(new SPI(fakeData, seed), AmazonCorrettoCryptoProvider.INSTANCE);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM_NAME;
    }

    static class SPI extends SecureRandomSpi {
        private static final long serialVersionUID = 1L;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest(ALGORITHM_NAME, SPI::runSelfTest);

        static SelfTestResult runSelfTest() {
            int tests = 0;

            try (final Scanner in = new Scanner(Loader.getTestData("ctr-drbg.txt"), StandardCharsets.US_ASCII.name())) {
                while (in.hasNext()) {
                    tests++;
                    final int bytesGenerated = in.nextInt() / 8;
                    final byte[] seed = Utils.decodeHex(in.next());
                    final byte[] entropy = Utils.decodeHex(in.next());
                    final byte[] expected = Utils.decodeHex(in.next());

                    final AesCtrDrbg drbg = new AesCtrDrbg(entropy, seed);
                    final byte[] output = new byte[bytesGenerated];
                    drbg.nextBytes(output);
                    drbg.nextBytes(output);
                    if (!Arrays.equals(expected, output)) {
                        SelfTestResult result = new SelfTestResult(
                                new AssertionError(String.format("Expected output did not match for inputs: " +
                                                      "(seed=%s, entropy=%s, expected=%s), actual=%s",
                                                      encodeHex(seed),
                                                      encodeHex(entropy),
                                                      encodeHex(expected),
                                                      encodeHex(output)
                                ))
                        );

                        getLogger("AmazonCorrettoCryptoProvider").severe(ALGORITHM_NAME + " failed self-test " + tests);
                        return result;
                    }
                }
            } catch (Throwable ex) {
                return new SelfTestResult(ex);
            }
            return new SelfTestResult(SelfTestStatus.PASSED);
        }

        private static String encodeHex(final byte[] output) {
            String hexChars = "0123456789abcdef";

            StringBuilder sb = new StringBuilder(output.length * 2);

            for (byte b : output) {
                sb.append(hexChars.charAt((b >> 4) & 0x0f));
                sb.append(hexChars.charAt(b & 0x0f));
            }

            return sb.toString();
        }

        private static final ThreadLocal<NativeDrgbState> state_ = new ThreadLocal<NativeDrgbState>() {
            @Override
            protected NativeDrgbState initialValue() {
                return new NativeDrgbState(instantiate(null, null));
            }
        };

        private final NativeDrgbState testState_;

        SPI() {
            this(null, null);
        }

        private SPI(byte[] fakeData, byte[] fakeSeed) {
            Loader.checkNativeLibraryAvailability();
            if (!AmazonCorrettoCryptoProvider.isRdRandSupported()) {
                throw new UnsupportedOperationException("RDRAND not supported");
            }

            final boolean inSelfTest = fakeData != null || fakeSeed != null;
            if (inSelfTest) {
                testState_ = new NativeDrgbState(instantiate(fakeSeed, fakeData));
            } else {
                testState_ = null;
                // Allow use only if we have already passed a self-test.
                SELF_TEST.assertSelfTestPassed();
            }
        }

        private NativeDrgbState getState() {
          return testState_ != null ? testState_ : state_.get();
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            final byte[] seed = new byte[numBytes];
            engineNextBytes(seed);
            return seed;
        }

        @Override
        protected void engineNextBytes(byte[] bytes) {
            int offset = 0;
            while (offset < bytes.length) {
                final int toGenerate = Math.min(MAX_SINGLE_REQUEST, bytes.length - offset);
                final int currentOffset = offset;
                getState().useVoid(ptr ->generate(ptr, bytes, currentOffset, toGenerate));
                offset += toGenerate;
            }
        }

        @Override
        protected void engineSetSeed(byte[] seed) {
            final byte[] actualSeed;
            if (seed.length != SEED_SIZE) {
                actualSeed = Arrays.copyOf(seed, SEED_SIZE);
            } else {
                actualSeed = seed;
            }
            getState().useVoid(ptr->reseed(ptr, actualSeed));
        }

        private static class NativeDrgbState extends NativeResource {
            private NativeDrgbState(long ptr) {
                super(ptr, AesCtrDrbg::releaseState);
            }
        }
    }
}
