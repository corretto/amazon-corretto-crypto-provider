// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.interfaces.DHKey;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

class EvpKeyAgreement extends KeyAgreementSpi {
    private static final int[] AES_KEYSIZES_BYTES = new int[]{16, 24, 32};
    private static final Pattern ALGORITHM_WITH_EXPLICIT_KEYSIZE = Pattern.compile("(\\S+?)(?:\\[(\\d+)\\])?");

    private final AmazonCorrettoCryptoProvider provider_;
    private final EvpKeyType keyType_;
    private final String algorithm_;
    private PrivateKey privKey = null;
    private byte[] privKeyDer = null;
    private byte[] secret = null;

    private static native byte[] agree(byte[] privateKeyDer, byte[] publicKeyDer, int keyType, boolean checkPrivateKey)
            throws InvalidKeyException;

    EvpKeyAgreement(AmazonCorrettoCryptoProvider provider, final String algorithm, final EvpKeyType keyType) {
        Loader.checkNativeLibraryAvailability();
        provider_ = provider;
        algorithm_ = algorithm;
        keyType_ = keyType;
    }

    @Override
    protected Key engineDoPhase(final Key key, final boolean lastPhase) throws InvalidKeyException,
            IllegalStateException {
        if (privKey == null) {
            throw new IllegalStateException("KeyAgreement has not been initialized");
        }

        if (!keyType_.publicKeyClass.isAssignableFrom(key.getClass())) {
            throw new InvalidKeyException("Expected key of type " + keyType_.publicKeyClass + " not " + key.getClass());
        }
        final byte[] pubKeyDer;
        try {
            pubKeyDer = keyType_.getKeyFactory().getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
        } catch (final InvalidKeySpecException | NullPointerException ex) {
            throw new InvalidKeyException(ex);
        }

        if (lastPhase) {
            // We do the actual agreement here because that is where key validation and thus exceptions
            // get thrown.
            secret = agree(privKeyDer, pubKeyDer, keyType_.nativeValue,
                provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY)
                );
            return null;
        } else if ("DH".equals(algorithm_)) {
            final DHParameterSpec dhParams = ((DHKey) privKey).getParams();
            try {
                final Key result = keyType_.getKeyFactory().generatePublic(new DHPublicKeySpec(
                    new BigInteger(1,
                        agree(privKeyDer, pubKeyDer, keyType_.nativeValue,
                            provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY)
                            )), // y
                    dhParams.getP(),
                    dhParams.getG()
                ));
                return result;
            } catch (final InvalidKeySpecException ex) {
                throw new RuntimeCryptoException(ex);
            }
        } else {
            secret = null;
            throw new IllegalStateException("Only single phase agreement is supported");
        }
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (privKey == null) {
            throw new IllegalStateException("KeyAgreement has not been initialized");
        }
        if (secret == null) {
            throw new IllegalStateException("KeyAgreement has not been completed");
        }
        final byte[] result = secret;
        reset();
        return result;
    }

    @Override
    protected SecretKey engineGenerateSecret(final String algorithm) throws IllegalStateException,
            NoSuchAlgorithmException, InvalidKeyException {
        byte[] secret = engineGenerateSecret();
        if (algorithm.equalsIgnoreCase("TlsPremasterSecret")) {
            if (algorithm_.equals("DH")) {
                // RFC 5246 Section 8.1.2 requires us to remove leading zeros
                // for DH premaster secrets. These are explicitly /not/ removed
                // for ECDH (RFC 4492, Section 5.10)
                secret = trimZeros(secret);
            }
            return new SecretKeySpec(secret, "TlsPremasterSecret");
        };
        final Matcher matcher = ALGORITHM_WITH_EXPLICIT_KEYSIZE.matcher(algorithm);
        if (matcher.matches()) {
            switch (matcher.group(1)) {
                case "AES":
                    String keySizeString = matcher.group(2);
                    int keyLength = 0;
                    boolean lengthFound = false;
                    if (keySizeString != null) {
                        keyLength = Integer.parseInt(keySizeString);
                        for (final int aesLength : AES_KEYSIZES_BYTES) {
                            if (aesLength == keyLength) {
                                lengthFound = true;
                                break;
                            }
                        }
                    } else {
                        for (final int aesLength : AES_KEYSIZES_BYTES) {
                            if (aesLength <= secret.length) {
                                keyLength = aesLength;
                                lengthFound = true;
                            }
                        }
                    }
                    if (!lengthFound || keyLength > secret.length) {
                        throw new InvalidKeyException("Invalid key length");
                    }
                    return new SecretKeySpec(secret, 0, keyLength, "AES");

                default:
                    throw new InvalidKeyException("Unsupported algorithm: " + matcher.group(1));
            }
        }
        throw new InvalidKeyException("Unrecognized algorithm: " + algorithm);
    }

    @Override
    protected int engineGenerateSecret(final byte[] sharedSecret, final int offset) throws IllegalStateException,
            ShortBufferException {
        final byte[] tmp = engineGenerateSecret();
        if (sharedSecret.length - offset < tmp.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(tmp, 0, sharedSecret, offset, tmp.length);
        reset();
        return tmp.length;
    }

    @Override
    protected void engineInit(final Key key, final SecureRandom ignored) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (!keyType_.privateKeyClass.isAssignableFrom(key.getClass())) {
            throw new InvalidKeyException("Expected key of type " + keyType_.privateKeyClass + " not " + key.getClass());
        }
        privKey = (PrivateKey) key;
        try {
            privKeyDer = keyType_.getKeyFactory().getKeySpec(key, PKCS8EncodedKeySpec.class).getEncoded();
        } catch (final InvalidKeySpecException ex) {
            throw new InvalidKeyException(ex);
        }
        reset();
    }

    @Override
    protected void engineInit(final Key key, final AlgorithmParameterSpec spec, final SecureRandom ignored)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("No algorithm parameter spec expected");
        }
        engineInit(key, ignored);
    }

    protected void reset() {
        secret = null;
    }

    private static byte[] trimZeros(final byte[] secret) {
        // According to other implementations, we don't appear
        // to need to worry about timing leaks of this data.
        int bytesToTrim = 0;
        while (bytesToTrim < secret.length && secret[bytesToTrim] == 0) {
            bytesToTrim++;
        }

        if (bytesToTrim == 0) {
            return secret;
        }
        return Arrays.copyOfRange(secret, bytesToTrim, secret.length);
    }

    static class ECDH extends EvpKeyAgreement {
        ECDH(AmazonCorrettoCryptoProvider provider) {
            super(provider, "ECDH", EvpKeyType.EC);
        }
    }

    static class DH extends EvpKeyAgreement {
        DH(AmazonCorrettoCryptoProvider provider) {
            super(provider, "DH", EvpKeyType.DH);
        }
    }
}
