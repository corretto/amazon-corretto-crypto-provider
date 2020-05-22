// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.util.Arrays;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

class EvpEcPublicKey extends EvpEcKey implements ECPublicKey {
    private static final long serialVersionUID = 1;

    private static native byte[] getPublicPointCoords(long ptr);

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
                final int fieldSizeBits = getParams().getCurve​().getField().getFieldSize();
                final int fieldSizeBytes = (fieldSizeBits + 7) / 8;

                final byte[] combinedCoords = use(EvpEcPublicKey::getPublicPointCoords);

                if (combinedCoords.length != (2 * fieldSizeBytes)) {
                    throw new RuntimeCryptoException("Unexpected result length when retrieving public key: " + combinedCoords.length);
                }

                // Offset constructor for BigInteger only exists in JDK 9+ so we need to split the array ourselves
                final byte[] x = Arrays.copyOfRange(combinedCoords, 0, fieldSizeBytes);
                final byte[] y = Arrays.copyOfRange(combinedCoords, fieldSizeBytes, fieldSizeBytes + fieldSizeBytes);

                w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            }
        }
        return w;
    }
}