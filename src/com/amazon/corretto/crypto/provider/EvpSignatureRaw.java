// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;

class EvpSignatureRaw extends EvpSignatureBase {
    private final AmazonCorrettoCryptoProvider provider_;
    private AccessibleByteArrayOutputStream buffer = new AccessibleByteArrayOutputStream(64, 1024*1024);

    private EvpSignatureRaw(AmazonCorrettoCryptoProvider provider, final EvpKeyType keyType, final int paddingType) {
        super(keyType, paddingType);
        provider_ = provider;
    }

    @Override protected void engineReset() {
        buffer.reset();
    }

    @Override protected void engineUpdate(final byte b) throws SignatureException {
        buffer.write(b & 0xFF);
    }

    @Override protected void engineUpdate(final byte[] b, final int off, final int len) throws SignatureException {
        buffer.write(b, off, len);
    }

    @Override protected void engineUpdate(final ByteBuffer input) {
        buffer.write(input);
    }

    @Override protected byte[] engineSign() throws SignatureException {
        try {
            return signRaw(
                    keyDer_, keyType_.nativeValue,
                    provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                    paddingType_,
                    null, 0,
                    buffer.getDataBuffer(), 0, buffer.size()
            );
        } finally {
            engineReset();
        }
    }

    @Override protected boolean engineVerify(final byte[] sigBytes) throws SignatureException {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    @Override protected boolean engineVerify(final byte[] sigBytes, final int offset, final int length) throws
            SignatureException {
        try {
            return verifyRaw(
                    keyDer_, keyType_.nativeValue, paddingType_,
                    null, 0,
                    buffer.getDataBuffer(), 0, buffer.size(),
                    sigBytes, offset, length
            );
        } finally {
            engineReset();
        }
    }

    private static native byte[] signRaw(
            byte[] keyDer, int keyType, boolean checkPrivateKey,
            int paddingType,
            String mgfMd, int saltLen,
            byte[] message, int offset, int length
    );

    private static native boolean verifyRaw(
            byte[] keyDer, int keyType, int paddingType,
            String mgfMd, int saltLen,
            byte[] message, int offset, int length,
            byte[] signature, int sigOffset, int sigLength
    );

    static final class NONEwithECDSA extends EvpSignatureRaw {
        NONEwithECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0);
        }
    }

    static final class NONEwithDSA extends EvpSignatureRaw {
        NONEwithDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0);
        }
    }
}
