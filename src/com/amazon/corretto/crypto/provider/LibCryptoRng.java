// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;

/**
 * A simple wrapper around the linked LibCrypto's RAND_bytes() API.
 */
public class LibCryptoRng extends SecureRandom {
    private static final String ALGORITHM_NAME = "LibCryptoRng";
    private static final long serialVersionUID = 1L;
    private static final int MAX_SINGLE_REQUEST = 8192;

    private static native long instantiate();

    private static native void generate(long ptr, byte[] bytes, int offset, int length);

    private static native void releaseState(long ptr);

    public LibCryptoRng() {
        super(new SPI(), AmazonCorrettoCryptoProvider.INSTANCE);
    }


    @Override
    public String getAlgorithm() {
        return ALGORITHM_NAME;
    }

    static class SPI extends SecureRandomSpi {
        private static final long serialVersionUID = 1L;
        static final SelfTestSuite.SelfTest SELF_TEST = new SelfTestSuite.SelfTest(ALGORITHM_NAME, LibCryptoRng.SPI::runSelfTest);

        static SelfTestResult runSelfTest() {
            LibCryptoRng rnd = new LibCryptoRng();

            /* Basic RNG self-test, do we generate different random numbers on repeat calls? */
            final long initialLong = rnd.nextLong();
            for (int trial = 0; trial < 10; trial++) {
                if (initialLong != rnd.nextLong()) {
                    return new SelfTestResult(SelfTestStatus.PASSED);
                }
            }
            return new SelfTestResult(SelfTestStatus.FAILED);
        }

        private static class NativeDrgbState extends NativeResource {
            private NativeDrgbState(long ptr) {
                super(ptr, LibCryptoRng::releaseState);
            }
        }

        private static final ThreadLocal<NativeDrgbState> state_ = new ThreadLocal<NativeDrgbState>() {
            @Override
            protected NativeDrgbState initialValue() {
                return new NativeDrgbState(instantiate());
            }
        };

        SPI() {
        }

        private NativeDrgbState getState() {
          return state_.get();
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
            // No way to mix entropy into AWS-LC RNG. No-op.
            return;
        }


    }
}
