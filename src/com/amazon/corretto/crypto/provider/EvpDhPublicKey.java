// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;

class EvpDhPublicKey extends EvpDhKey implements DHPublicKey {
    private static final long serialVersionUID = 1;

    private static native byte[] getY(long ptr);

    protected BigInteger y;

    EvpDhPublicKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpDhPublicKey(InternalKey key) {
        super(key, true);
    }

    @Override
    public BigInteger getY() {
        synchronized (this) {
            if (y == null) {
                y = nativeBN(EvpDhPublicKey::getY);
            }
        }
        return y;
    }
}