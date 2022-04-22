// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;

class EvpEcPrivateKey extends EvpEcKey implements ECPrivateKey, CanDerivePublicKey<EvpEcPublicKey> {
    private static final long serialVersionUID = 1;

    private static native byte[] getPrivateValue(long ptr);

    protected BigInteger s;

    EvpEcPrivateKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpEcPrivateKey(InternalKey key) {
        super(key, false);
    }

    @Override
    public EvpEcPublicKey getPublicKey() {
        ephemeral = false; // Once our internal key could be elsewhere, we can no longer safely release it when done
        return new EvpEcPublicKey(internalKey);
    }

    @Override
    public BigInteger getS() {
        synchronized (this) {
            if (s == null) {
                s = nativeBN(EvpEcPrivateKey::getPrivateValue);
            }
        }
        return s;
    }

    @Override
    protected synchronized void destroyJavaState() {
        super.destroyJavaState();
        s = null;
    }
}
