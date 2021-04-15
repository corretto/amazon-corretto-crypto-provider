// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

class EvpRsaPublicKey extends EvpRsaKey implements RSAPublicKey {
    private static final long serialVersionUID = 1;

    private BigInteger publicExponent;

    EvpRsaPublicKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpRsaPublicKey(InternalKey key) {
        super(key, true);
    }

    @Override
    public BigInteger getPublicExponent() {
        synchronized (this) {
            if (publicExponent == null) {
                publicExponent = nativeBN(EvpRsaKey::getPublicExponent);
            }
        }
        return publicExponent;
    }
}
