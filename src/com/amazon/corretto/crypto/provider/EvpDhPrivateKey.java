// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;

class EvpDhPrivateKey extends EvpDhKey implements DHPrivateKey {
    private static final long serialVersionUID = 1;

    private static native byte[] getX(long ptr);

    protected BigInteger x;

    EvpDhPrivateKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpDhPrivateKey(InternalKey key) {
        super(key, false);
    }

    EvpDhPublicKey getPublicKey() {
        return new EvpDhPublicKey(internalKey);
    }

    @Override
    public BigInteger getX() {
        synchronized (this) {
            if (x == null) {
                x = nativeBN(EvpDhPrivateKey::getX);
            }
        }
        return x;
    }
}