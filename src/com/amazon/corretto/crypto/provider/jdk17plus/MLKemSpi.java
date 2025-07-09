// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.jdk17plus;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;

/**
 * Implementation of ML-KEM SPI classes.
 */
public abstract class MLKemSpi implements KEMSpi {

    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom) 
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) 
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /** ML-KEM-512 implementation. */
    public static final class MLKem512 extends MLKemSpi {
        // ML-KEM-512 specific implementation
    }

    /** ML-KEM-768 implementation. */
    public static final class MLKem768 extends MLKemSpi {
        // ML-KEM-768 specific implementation
    }

    /** ML-KEM-1024 implementation. */
    public static final class MLKem1024 extends MLKemSpi {
        // ML-KEM-1024 specific implementation
    }
}
