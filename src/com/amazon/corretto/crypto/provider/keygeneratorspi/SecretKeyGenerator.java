// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.keygeneratorspi;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Supplier;

public class SecretKeyGenerator extends KeyGeneratorSpi {
    private final Supplier<SecureRandom> defaultSecureRandomSupplier;
    private final SecretKeyProperties secretKeyProperties;
    private Optional<SecureRandom> secureRandom;
    private int keySize;

    // This class is instantiated internally by ACCP, and it expects non-null arguments; moreover,
    // defaultSecureRandomSupplier.get() cannot return null.
    public SecretKeyGenerator(final Supplier<SecureRandom> defaultSecureRandomSupplier, final SecretKeyProperties secretKeyProperties) {
        this.defaultSecureRandomSupplier = defaultSecureRandomSupplier;
        this.secretKeyProperties = secretKeyProperties;
        this.secureRandom = Optional.empty();
        this.keySize = secretKeyProperties.defaultKeySize();
    }

    @Override
    protected void engineInit(final SecureRandom random) {
        secureRandom = Optional.ofNullable(random);
    }

    @Override
    protected void engineInit(final AlgorithmParameterSpec params, final SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("SecretKeyGenerator does not support initialization with AlgorithmParameterSpec.");
    }

    @Override
    protected void engineInit(final int keySize, final SecureRandom random) {
        secretKeyProperties.checkKeySizeIsValid(keySize);
        this.keySize = keySize;
        this.secureRandom = Optional.ofNullable(random);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        final byte[] keyBytes = new byte[keySize / 8];
        final SecureRandom srand = secureRandom.orElseGet(defaultSecureRandomSupplier);
        srand.nextBytes(keyBytes);
        final SecretKeySpec result = new SecretKeySpec(keyBytes, secretKeyProperties.getName());
        Arrays.fill(keyBytes, (byte) 0);
        return result;
    }
}
