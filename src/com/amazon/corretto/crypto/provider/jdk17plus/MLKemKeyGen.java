// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.jdk17plus;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public abstract class MLKemKeyGen extends KeyPairGeneratorSpi {
    protected SecureRandom random;
    protected int keysize;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ML-KEM does not use algorithm parameters");
    }

    @Override
    public KeyPair generateKeyPair() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    public static class MLKemKeyGen512 extends MLKemKeyGen {
        @Override
        public void initialize(int keysize, SecureRandom random) {
            if (keysize != 512) {
                throw new IllegalArgumentException("ML-KEM-512 requires keysize 512");
            }
            super.initialize(keysize, random);
        }
    }

    public static class MLKemKeyGen768 extends MLKemKeyGen {
        @Override
        public void initialize(int keysize, SecureRandom random) {
            if (keysize != 768) {
                throw new IllegalArgumentException("ML-KEM-768 requires keysize 768");
            }
            super.initialize(keysize, random);
        }
    }

    public static class MLKemKeyGen1024 extends MLKemKeyGen {
        @Override
        public void initialize(int keysize, SecureRandom random) {
            if (keysize != 1024) {
                throw new IllegalArgumentException("ML-KEM-1024 requires keysize 1024");
            }
            super.initialize(keysize, random);
        }
    }
}
