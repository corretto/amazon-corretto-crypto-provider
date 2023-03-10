// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.keygeneratorspi;

import javax.crypto.Cipher;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public final class AesSecretKeyProperties implements SecretKeyProperties {

    private AesSecretKeyProperties() {
        // no op
    }

    public static final AesSecretKeyProperties INSTANCE = new AesSecretKeyProperties();
    private static final String NAME = "AES";

    private static final Set<Integer> AES_VALID_KEY_SIZES = aesValidKeySizes();

    private static Set<Integer> aesValidKeySizes() {
        final Set<Integer> result = new HashSet<>();
        result.add(128);
        result.add(192);
        result.add(256);
        return result;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public int defaultKeySize() {
        try {
            return Math.min(256, Cipher.getMaxAllowedKeyLength("AES"));
        } catch (final NoSuchAlgorithmException e) {
            throw new AssertionError("This is an impossible case.", e);
        }
    }

    @Override
    public void checkKeySizeIsValid(final int keySize) {
        if (!AES_VALID_KEY_SIZES.contains(keySize)) {
            throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
        }
    }
}
