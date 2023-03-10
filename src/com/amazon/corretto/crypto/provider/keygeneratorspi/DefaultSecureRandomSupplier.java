// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.keygeneratorspi;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.LibCryptoRng;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Supplier;

public final class DefaultSecureRandomSupplier implements Supplier<SecureRandom> {

    private DefaultSecureRandomSupplier() {
        // no op
    }

    public static final DefaultSecureRandomSupplier INSTANCE = new DefaultSecureRandomSupplier();

    @Override
    public SecureRandom get() {
        try {
            return SecureRandom.getInstance(LibCryptoRng.ALGORITHM_NAME, AmazonCorrettoCryptoProvider.INSTANCE);
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError(LibCryptoRng.ALGORITHM_NAME + " is not a provided by AmazonCorrettoCryptoProvider", e);
        }
    }
}
