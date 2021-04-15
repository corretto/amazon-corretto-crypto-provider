// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAKey;

abstract class EvpRsaKey extends EvpKey implements RSAKey {
    private static final long serialVersionUID = 1;
    
    protected BigInteger modulus;

    protected static native byte[] getModulus(long ptr);
    protected static native byte[] getPublicExponent(long ptr);

    EvpRsaKey(InternalKey key, boolean isPublicKey)  {
        super(key, EvpKeyType.RSA, isPublicKey);
    }

    @Override
    public BigInteger getModulus() {
        synchronized (this) {
            if (modulus == null) {
                modulus = nativeBN(EvpRsaKey::getModulus);
            }
        }

        return modulus;
    }
    
}
