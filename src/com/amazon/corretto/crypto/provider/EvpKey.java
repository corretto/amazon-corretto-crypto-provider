// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.Destroyable;

abstract class EvpKey implements Key, Destroyable {
    private static final long serialVersionUID = 1;

    protected final InternalKey internalKey;
    protected final EvpKeyType type;
    protected final boolean isPublicKey;
    protected boolean ephemeral = false;

    protected byte[] encoded;
    protected Integer cachedHashCode;

    private static native void releaseKey(long ptr);
    private static native byte[] encodePublicKey(long ptr);
    private static native byte[] encodePrivateKey(long ptr);
    protected static native byte[] getDerEncodedParams(long ptr);

    EvpKey(final InternalKey key, final EvpKeyType type, final boolean isPublicKey) {
        this.internalKey = key;
        this.type = type;
        this.isPublicKey = isPublicKey;
    }

    boolean isEphemeral() {
        return ephemeral;
    }

    void setEphemeral(final boolean ephemeral) {
        this.ephemeral = ephemeral;
    }

    void releaseEphemeral() {
        if (ephemeral) {
            destroy();
        }
    }

    // @CheckReturnValue // Restore once replacement for JSR-305 available
    <T, X extends Throwable> T use(final MiscInterfaces.ThrowingLongFunction<T, X> function) throws X {
        return internalKey.use(function);
    }

    <X extends Throwable> void useVoid(final MiscInterfaces.ThrowingLongConsumer<X> function) throws X {
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
        initEncoded();
        return encoded != null ? encoded.clone() : encoded;
    }

    protected void initEncoded() {
        if (encoded == null) {
            synchronized (this) {
                if (encoded == null) {
                    encoded = isPublicKey ? use(EvpKey::encodePublicKey) : use(EvpKey::encodePrivateKey);
                }
            }
        }
    }

    protected <X extends Throwable> BigInteger nativeBN(final MiscInterfaces.ThrowingLongFunction<byte[], X> fn)
            throws X {
        byte[] raw = use(fn::apply);
        return new BigInteger(1, raw);
    }

    protected <T extends AlgorithmParameterSpec> T nativeParams(final Class<T> paramSpec) {
        byte[] encodedParams = use(EvpKey::getDerEncodedParams);
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(type.jceName);
            params.init(encodedParams);
            return params.getParameterSpec(paramSpec);
        } catch (final GeneralSecurityException | IOException ex) {
            throw new RuntimeCryptoException("Unable to deserialize parameters: "
                + Base64.getEncoder().encodeToString(encoded), ex);
        }
    }

    /**
     * This method will be called by @{link #destroy()} after calling @{code internalKey.release()}.
     */
    protected synchronized void destroyJavaState() {
        // NOP
    }

    @Override
    public boolean equals(final Object obj) {
        // We try to avoid comparing the encoded values
        // because it may be slow and may pull secret data into the Java heap
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Key)) { // Implicit null check
            return false;
        }
        final Key other = (Key) obj;
        if (!getAlgorithm().equalsIgnoreCase(other.getAlgorithm())) {
            return false;
        }

        final byte[] otherEncoded;
        if (obj.getClass().equals(getClass())) {
            // If it is also an EvpKey then we can see if the internal key is the same
            EvpKey evpOther = (EvpKey) obj;
            if (internalKey.equals(evpOther.internalKey)) {
                return true;
            }
            // If it is also an EvpKey then we can grab the other encoded value without copying it
            evpOther.initEncoded();
            otherEncoded = evpOther.encoded;
        } else {
            otherEncoded = other.getEncoded();
        }

        // Constant time equality check
        initEncoded();
        return MessageDigest.isEqual(encoded, otherEncoded);
    }

    @Override
    public int hashCode() {
        // TODO: Consider ways to avoid exposing the entire encoded object ot Java for private keys just for a hashCode
        if (cachedHashCode == null) {
            synchronized (this) {
                if (cachedHashCode != null) {
                    return cachedHashCode;
                }
                initEncoded();
                // Selected to match implementations of sun.security.pkcs.PKCS8Key and sun.security.x509.X509Key
                int workingValue = 0;
                if (isPublicKey) {
                    workingValue = encoded.length;
                    for (final byte b : encoded) {
                        workingValue += (b & 0xff) * 37;
                    }
                } else {
                    if (Utils.getJavaVersion() >= 17) {
                        workingValue = Arrays.hashCode(encoded);
                    } else {
                        for (int idx = 0; idx < encoded.length; idx++) {
                            workingValue += encoded[idx] * idx;
                        }
                    }
                }
                cachedHashCode = workingValue;
            }
        }
        return cachedHashCode;
    }

    @Override
    public boolean isDestroyed() {
        return internalKey.isReleased();
    }

    @Override
    public synchronized void destroy() {
        if (isDestroyed()) {
            throw new IllegalStateException("Already destroyed");
        }
        internalKey.release();
        destroyJavaState();
    }

    protected static class InternalKey extends NativeResource {
        InternalKey(final long ptr) {
            super(ptr, EvpKey::releaseKey, true);
        }
    }

    protected interface CanDerivePublicKey<T extends EvpKey & PublicKey> {
        T getPublicKey();
    }
}
