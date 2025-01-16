// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;

class EvpSignatureRaw extends EvpSignatureBase {
  private AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);

  private EvpSignatureRaw(
      final AmazonCorrettoCryptoProvider provider,
      final EvpKeyType keyType,
      final int paddingType) {
    super(provider, keyType, paddingType, 0 /* No digest */);
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
          ptr -> signRaw(ptr, paddingType_, 0, 0, buffer.getDataBuffer(), 0, buffer.size()));
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
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length);

  private static native boolean verifyRaw(
      long publicKey,
      int paddingType,
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

  static final class MlDSA extends EvpSignatureRaw {
    MlDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MlDSA, 0);
    }
  }
}
