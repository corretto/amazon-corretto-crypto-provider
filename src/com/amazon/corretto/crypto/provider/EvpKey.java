// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.function.Function;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;


abstract class EvpKey implements Key {
    private static final long serialVersionUID = 1;

    protected final InternalKey internalKey;
    protected final EvpKeyType type;
    protected final boolean isPublicKey;
    protected boolean ephemeral = false;
    
    private byte[] encoded;

    private static native void releaseKey(long ptr);
    private static native byte[] encodePublicKey(long ptr);
    private static native byte[] encodePrivateKey(long ptr);
    protected static native byte[] getDerEncodedParams(long ptr);

    EvpKey(InternalKey key, EvpKeyType type, boolean isPublicKey) {
        this.internalKey = key;
        this.type = type;
        this.isPublicKey = isPublicKey;
    }

    boolean isEphemeral() {
        return ephemeral;
    }

    void setEphemeral(boolean ephemeral) {
        this.ephemeral = ephemeral;
    }

    void releaseEphemeral() {
        if (ephemeral) {
            internalKey.release();
        }
    }

    /**
     * Calls the supplied {@link LongFunction} passing in the raw handle as a parameter and return
     * the result.
     */
    // @CheckReturnValue // Restore once replacement for JSR-305 available
    <T> T use(LongFunction<T> function) {
        return internalKey.use(function);
    }

    /**
     * Calls the supplied {@link LongConsumer} passing in the raw handle as a parameter.
     */
    void useVoid(LongConsumer function) {
        internalKey.useVoid(function);
    }

    @Override
    public String getAlgorithm() {
        return type.jceName;
    }

    @Override
    public String getFormat() {
        return isPublicKey ? "X.509" :  "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        synchronized (this) {
            if (encoded == null) {
                encoded = isPublicKey ? use(EvpKey::encodePublicKey) : use(EvpKey::encodePrivateKey);
            }
        }
        return encoded != null ? encoded.clone() : encoded;
    }

    protected BigInteger nativeBN(Function<Long, byte[]> fn) {
        byte[] raw = use(fn::apply);
        return new BigInteger(1, raw);
    }

    protected <T extends AlgorithmParameterSpec> T nativeParams(Class<T> paramSpec) {
        byte[] encoded = use(EvpKey::getDerEncodedParams);
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(type.jceName);
            params.init(encoded);
            return params.getParameterSpec(paramSpec);
        } catch (final GeneralSecurityException | IOException ex) {
            throw new RuntimeCryptoException("Unable to deserialize parameters: " + Base64.getEncoder().encodeToString(encoded), ex);
        }
    }

    protected static class InternalKey extends NativeResource {
        InternalKey(long ptr) {
            super(ptr, EvpKey::releaseKey, true);
        }
    }
}