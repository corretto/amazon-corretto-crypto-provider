// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

class EvpRsaPrivateCrtKey extends EvpRsaPrivateKey implements RSAPrivateCrtKey {
    private static final long serialVersionUID = 1;

    protected BigInteger crtCoef;
    protected BigInteger expP;
    protected BigInteger expQ;
    protected BigInteger primeP;
    protected BigInteger primeQ;
    protected BigInteger publicExponent;

    protected static native void getCrtParams(long ptr, byte[] crtCoefArr, byte[] expPArr, byte[] expQArr, byte[] primePArr, byte[] primeQArr, byte[] publicExponentArr, byte[] privateExponentArr);

    EvpRsaPrivateCrtKey(long ptr) {
        super(new InternalKey(ptr));
    }

    EvpRsaPublicKey getPublicKey() {
        return new EvpRsaPublicKey(internalKey);
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

    protected synchronized void initBNs() {
        if (privateExponent != null) {
            return;
        }
        // Everything will be no larger than the modulus.
        final BigInteger modulus = getModulus();
        final int byteLength = (modulus.bitLength() + 7) / 8;

        final byte[] crtCoefArr = new byte[byteLength];
        final byte[] expPArr = new byte[byteLength];
        final byte[] expQArr = new byte[byteLength];
        final byte[] primePArr = new byte[byteLength];
        final byte[] primeQArr = new byte[byteLength];
        final byte[] publicExponentArr = new byte[byteLength];
        final byte[] privateExponentArr = new byte[byteLength];

        useVoid(p -> getCrtParams(p, crtCoefArr, expPArr, expQArr, primePArr, primeQArr, publicExponentArr, privateExponentArr));

        crtCoef = new BigInteger(1, crtCoefArr);
        expP = new BigInteger(1, expPArr);
        expQ = new BigInteger(1, expQArr);
        primeP = new BigInteger(1, primePArr);
        primeQ = new BigInteger(1, primeQArr);
        publicExponent = new BigInteger(1, publicExponentArr);
        privateExponent = new BigInteger(1, privateExponentArr);
    }

    @Override
    public BigInteger getPrivateExponent() {
        initBNs();
        return privateExponent;
    }

    @Override
    public BigInteger getCrtCoefficient​() {
        initBNs();
        return crtCoef;
    }

    @Override
    public BigInteger getPrimeExponentP​() {
        initBNs();
        return expP;
    }

    @Override
    public BigInteger getPrimeExponentQ​() {
        initBNs();
        return expQ;
    }

    @Override
    public BigInteger getPrimeP​() {
        initBNs();
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ​() {
        initBNs();
        return primeQ;
    }
}