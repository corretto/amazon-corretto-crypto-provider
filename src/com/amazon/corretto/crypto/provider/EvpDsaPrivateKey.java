// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;

class EvpDsaPrivateKey extends EvpDsaKey implements DSAPrivateKey {
    private static final long serialVersionUID = 1;
    
    private static native byte[] getX(long ptr);

    protected BigInteger x;

    EvpDsaPrivateKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpDsaPrivateKey(InternalKey key) {
        super(key, false);
    }

    EvpDsaPublicKey getPublicKey() {
        return new EvpDsaPublicKey(internalKey);
    }

    @Override
    public BigInteger getX() {
        synchronized (this) {
            if (x == null) {
                x = nativeBN(EvpDsaPrivateKey::getX);
            }
        }
        return x;
    }

    @Override
    protected synchronized void destroyJavaState() {
        super.destroyJavaState();
        x = null;
    }
}
