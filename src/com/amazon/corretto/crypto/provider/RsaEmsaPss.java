// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;

final class RsaEmsaPss extends EvpSignatureBase {
  private AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);

  RsaEmsaPss(final AmazonCorrettoCryptoProvider provider) {
    super(provider, EvpKeyType.RSA, RSA_PKCS1_PSS_PADDING, 0, false);
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  @Override
  protected void engineUpdate(final byte b) throws SignatureException {
    final int expectedDigestLen = Utils.getMdLen(digest_);
    if (buffer.size() >= expectedDigestLen) {
      throw new SignatureException(
          "Input exceeds digest length. Expected "
              + expectedDigestLen
              + " bytes, already have "
              + buffer.size());
    }
    buffer.write(b & 0xFF);
  }

  @Override
  protected void engineUpdate(final byte[] b, final int off, final int len)
      throws SignatureException {
    final int expectedDigestLen = Utils.getMdLen(digest_);
    if (buffer.size() + len > expectedDigestLen) {
      throw new SignatureException(
          "Input exceeds digest length. Expected "
              + expectedDigestLen
              + " bytes, would have "
              + (buffer.size() + len));
    }
    buffer.write(b, off, len);
  }

  @Override
  protected void engineUpdate(final ByteBuffer input) {
    final int expectedDigestLen = Utils.getMdLen(digest_);
    final int len = input.remaining();
    if (buffer.size() + len > expectedDigestLen) {
      throw new RuntimeException(
          new SignatureException(
              "Input exceeds digest length. Expected "
                  + expectedDigestLen
                  + " bytes, would have "
                  + (buffer.size() + len)));
    }
    buffer.write(input);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    try {
      ensureInitialized(true);
      final int expectedDigestLen = Utils.getMdLen(digest_);
      if (buffer.size() != expectedDigestLen) {
        throw new SignatureException(
            "Input must equal digest length. Expected "
                + expectedDigestLen
                + " bytes, got "
                + buffer.size());
      }
      return key_.use(
          ptr ->
              signEmsaPss(
                  ptr, digest_, pssMgfMd_, pssSaltLen_, buffer.getDataBuffer(), 0, buffer.size()));
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
      final int expectedDigestLen = Utils.getMdLen(digest_);
      if (buffer.size() != expectedDigestLen) {
        throw new SignatureException(
            "Input must equal digest length. Expected "
                + expectedDigestLen
                + " bytes, got "
                + buffer.size());
      }
      sniffTest(sigBytes, offset, length);
      return key_.use(
          ptr ->
              verifyEmsaPss(
                  ptr,
                  digest_,
                  pssMgfMd_,
                  pssSaltLen_,
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

  @Override
  protected boolean isBufferEmpty() {
    return buffer.size() == 0;
  }

  private static native byte[] signEmsaPss(
      long privateKey, long hashMd, long mgfMd, int saltLen, byte[] digest, int offset, int length);

  private static native boolean verifyEmsaPss(
      long publicKey,
      long hashMd,
      long mgfMd,
      int saltLen,
      byte[] digest,
      int offset,
      int length,
      byte[] signature,
      int sigOffset,
      int sigLength)
      throws SignatureException;
}
