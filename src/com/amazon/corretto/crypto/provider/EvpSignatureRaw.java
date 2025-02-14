// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;

class EvpSignatureRaw extends EvpSignatureBase {
  private AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);
  private final boolean preHash_;

  private EvpSignatureRaw(
      final AmazonCorrettoCryptoProvider provider,
      final EvpKeyType keyType,
      final int paddingType) {
    this(provider, keyType, paddingType, false);
  }

  private EvpSignatureRaw(
      final AmazonCorrettoCryptoProvider provider,
      final EvpKeyType keyType,
      final int paddingType,
      final boolean preHash) {
    super(provider, keyType, paddingType, 0 /* No digest */);
    preHash_ = preHash;
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  @Override
  protected void engineUpdate(final byte b) throws SignatureException {
    buffer.write(b & 0xFF);
  }

  @Override
  protected void engineUpdate(final byte[] b, final int off, final int len)
      throws SignatureException {
    buffer.write(b, off, len);
  }

  @Override
  protected void engineUpdate(final ByteBuffer input) {
    buffer.write(input);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    try {
      ensureInitialized(true);
      return key_.use(
          ptr ->
              signRaw(ptr, paddingType_, preHash_, 0, 0, buffer.getDataBuffer(), 0, buffer.size()));
    } finally {
      engineReset();
    }
  }

  @Override
  protected boolean engineVerify(final byte[] sigBytes) throws SignatureException {
    return engineVerify(sigBytes, 0, sigBytes.length);
  }

  @Override
  protected boolean engineVerify(final byte[] sigBytes, final int offset, final int length)
      throws SignatureException {
    try {
      ensureInitialized(false);
      sniffTest(sigBytes, offset, length);
      return key_.use(
          ptr ->
              verifyRaw(
                  ptr,
                  paddingType_,
                  preHash_,
                  0,
                  0,
                  buffer.getDataBuffer(),
                  0,
                  buffer.size(),
                  sigBytes,
                  offset,
                  length));
    } finally {
      engineReset();
    }
  }

  protected boolean isBufferEmpty() {
    return buffer.size() == 0;
  }

  private static native byte[] signRaw(
      long privateKey,
      int paddingType,
      boolean preHash,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length);

  private static native boolean verifyRaw(
      long publicKey,
      int paddingType,
      boolean preHash,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length,
      byte[] signature,
      int sigOffset,
      int sigLength)
      throws SignatureException;

  static final class NONEwithECDSA extends EvpSignatureRaw {
    NONEwithECDSA(AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0);
    }
  }

  static final class Ed25519 extends EvpSignatureRaw {
    Ed25519(AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EdDSA, 0);
    }
  }

  static final class MLDSA extends EvpSignatureRaw {
    MLDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MLDSA, 0);
    }
  }

  static final class MLDSAExtMu extends EvpSignatureRaw {
    MLDSAExtMu(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MLDSA, 0, /*preHash*/ true);
    }
  }
}
