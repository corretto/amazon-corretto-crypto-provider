// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.util.Arrays;
import java.security.interfaces.ECPrivateKey;

class EvpEcPrivateKey extends EvpEcKey implements ECPrivateKey {
    private static final long serialVersionUID = 1;

    private static native byte[] getPrivateValue(long ptr);

    protected BigInteger s;

    EvpEcPrivateKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpEcPrivateKey(InternalKey key) {
        super(key, false);
    }
    
    EvpEcPublicKey getPublicKey() {
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
