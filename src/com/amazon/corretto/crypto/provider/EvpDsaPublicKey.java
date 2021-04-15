// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;

class EvpDsaPublicKey extends EvpDsaKey implements DSAPublicKey {
    private static final long serialVersionUID = 1;

    protected static native byte[] getY(long ptr);

    protected BigInteger y;

    EvpDsaPublicKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpDsaPublicKey(InternalKey key) {
        super(key, true);
    }

    @Override
    public BigInteger getY() {
        synchronized (this) {
            if (y == null) {
                y = nativeBN(EvpDsaPublicKey::getY);
            }
        }
        return y;
    }
}
