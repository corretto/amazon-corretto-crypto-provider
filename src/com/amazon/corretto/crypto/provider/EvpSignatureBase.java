// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

abstract class EvpSignatureBase extends SignatureSpi {
    protected static final int RSA_PKCS1_PADDING = 1;
    protected final EvpKeyType keyType_;
    protected final int paddingType_;
    protected Key key_ = null;
    protected byte[] keyDer_ = null;
    protected boolean signMode;
    protected int keyUsageCount_ = 0;
    protected EvpContext ctx_ = null;

    EvpSignatureBase(
            final EvpKeyType keyType,
            final int paddingType
    ) {
        keyType_ = keyType;
        paddingType_ = paddingType;
    }

    protected abstract void engineReset();

    /**
     * Destroys the native context.
     *
     * @param ctx
     *            native context
     */
    private static native void destroyContext(long ctx);

    @Override
    protected synchronized void engineInitSign(final PrivateKey privateKey) throws InvalidKeyException {
        if (key_ != privateKey) {
            if (!keyType_.jceName.equalsIgnoreCase(privateKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            keyUsageCount_ = 0;
            if (ctx_ != null) {
                ctx_.release();
                ctx_ = null;
            }
            key_ = privateKey;
            try {
                keyDer_ = keyType_.getKeyFactory().getKeySpec(privateKey, PKCS8EncodedKeySpec.class).getEncoded();
            } catch (final InvalidKeySpecException ex) {
                key_ = null;
                keyDer_ = null;
                throw new InvalidKeyException(ex);
            }
        }
        signMode = true;
        engineReset();
    }

    @Override
    protected synchronized void engineInitVerify(final PublicKey publicKey) throws InvalidKeyException {
        if (key_ != publicKey) {
            if (!keyType_.jceName.equalsIgnoreCase(publicKey.getAlgorithm())) {
                throw new InvalidKeyException();
            }
            keyUsageCount_ = 0;
            if (ctx_ != null) {
                ctx_.release();
                ctx_ = null;
            }
            key_ = publicKey;
            try {
                keyDer_ = keyType_.getKeyFactory().getKeySpec(publicKey, X509EncodedKeySpec.class).getEncoded();
            } catch (final InvalidKeySpecException ex) {
                key_ = null;
                keyDer_ = null;
                throw new InvalidKeyException(ex);
            }

        }
        signMode = false;
        engineReset();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(final String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected void engineSetParameter(final String param, final Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters supported by this algorithm");
        }
    }

    @Override
    protected synchronized AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Ensures that we are properly initialized for the current mode of operation if specified.
     *
     * @param mode
     *            {@code true} if we're trying to sign data and {@code false} if we are trying to
     *            verify. If this value is {@code null} then it does not check to ensure it is
     *            initialized for a specific mode.
     * @throws SignatureException
     *             if we are not properly initialized
     */
    protected void ensureInitialized(final Boolean mode) throws SignatureException {
        // Code coverage is low as the java.security.Signature object actually
        // detects these cases before it reaches us.
        if (key_ == null) {
            throw new SignatureException("Not initialized");
        }
        if (mode != null && mode.booleanValue() != signMode) {
            throw new SignatureException("Incorrect mode for operation");
        }
    }

    protected static final class EvpContext extends NativeResource {
        protected EvpContext(final long ptr) {
            super(ptr, EvpSignatureBase::destroyContext);
        }
    }

}
