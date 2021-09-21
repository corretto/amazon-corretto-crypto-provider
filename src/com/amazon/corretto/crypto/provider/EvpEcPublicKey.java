// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

class EvpEcPublicKey extends EvpEcKey implements ECPublicKey {
    private static final long serialVersionUID = 1;

    private static native void getPublicPointCoords(long ptr, byte[] x, byte[] y);

    protected ECPoint w;

    EvpEcPublicKey(long ptr) {
        this(new InternalKey(ptr));
    }
    
    EvpEcPublicKey(InternalKey key) {
        super(key, true);
    }

    @Override
    public ECPoint getW() {
        synchronized (this) {
            if (w == null) {
                final int fieldSizeBits = getParams().getCurve().getField().getFieldSize();
                final int fieldSizeBytes = (fieldSizeBits + 7) / 8;

                final byte[] x = new byte[fieldSizeBytes];
                final byte[] y = new byte[fieldSizeBytes];

                useVoid(ptr -> getPublicPointCoords(ptr, x, y));

                w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            }
        }
        return w;
    }
}
