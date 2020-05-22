// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

class EvpRsaPrivateKey extends EvpRsaKey implements RSAPrivateKey {
    private static final long serialVersionUID = 1;
    
    protected BigInteger privateExponent;

    protected static native byte[] getPrivateExponent(long ptr);

    EvpRsaPrivateKey(long ptr) {
        this(new InternalKey(ptr));
    }

    EvpRsaPrivateKey(InternalKey key) {
        super(key, false);
    }

    @Override
    public BigInteger getPrivateExponent() {
        synchronized (this) {
            if (privateExponent == null) {
                privateExponent = nativeBN(EvpRsaPrivateKey::getPrivateExponent);
            }
        }

        return privateExponent;
    }
}