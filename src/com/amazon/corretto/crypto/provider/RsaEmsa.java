// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

class RsaEmsa extends EvpSignatureBase {
  private AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);

  protected RsaEmsa(final AmazonCorrettoCryptoProvider provider, final int paddingType) {
    super(provider, EvpKeyType.RSA, paddingType, 0, false);
  }

  protected RsaEmsa(
      final AmazonCorrettoCryptoProvider provider, final int paddingType, final long digest) {
    super(provider, EvpKeyType.RSA, paddingType, digest, false);
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
      if (paddingType_ == RSA_PKCS1_PADDING) {
        return key_.use(ptr -> signEmsa(ptr, digest_, buffer.getDataBuffer(), 0, buffer.size()));
      } else {
        return key_.use(
            ptr ->
                signEmsaPss(
                    ptr,
                    digest_,
                    pssMgfMd_,
                    pssSaltLen_,
                    buffer.getDataBuffer(),
                    0,
                    buffer.size()));
      }
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
      if (paddingType_ == RSA_PKCS1_PADDING) {
        return key_.use(
            ptr ->
                verifyEmsa(
                    ptr,
                    digest_,
                    buffer.getDataBuffer(),
                    0,
                    buffer.size(),
                    sigBytes,
                    offset,
                    length));
      } else {
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
      }
    } finally {
      engineReset();
    }
  }

  @Override
  protected boolean isBufferEmpty() {
    return buffer.size() == 0;
  }

  @Override
  protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (paddingType_ == RSA_PKCS1_PADDING) {
      if (params instanceof PSSParameterSpec) {
        // For PKCS#1 v1.5, accept PSSParameterSpec but only extract the digest algorithm.
        // MGF, salt length, and trailer are ignored since they are PSS-specific.
        final PSSParameterSpec pssParams = (PSSParameterSpec) params;
        if (!isBufferEmpty()) {
          throw new IllegalStateException(
              "Cannot update parameters with buffered data, reset Signature.");
        }
        try {
          digest_ = Utils.getMdPtr(pssParams.getDigestAlgorithm());
        } catch (Exception e) {
          throw new InvalidAlgorithmParameterException(
              "Unsupported digest: " + pssParams.getDigestAlgorithm());
        }
      } else {
        throw new InvalidAlgorithmParameterException(
            "Only PSSParameterSpec is accepted (to select digest algorithm)");
      }
    } else {
      super.engineSetParameter(params);
    }
  }

  @Override
  protected synchronized AlgorithmParameters engineGetParameters() {
    if (paddingType_ == RSA_PKCS1_PADDING) {
      return null;
    }
    return super.engineGetParameters();
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

  private static native byte[] signEmsa(
      long privateKey, long hashMd, byte[] digest, int offset, int length);

  private static native boolean verifyEmsa(
      long publicKey,
      long hashMd,
      byte[] digest,
      int offset,
      int length,
      byte[] signature,
      int sigOffset,
      int sigLength)
      throws SignatureException;

  static final class Pss extends RsaEmsa {
    Pss(final AmazonCorrettoCryptoProvider provider) {
      super(provider, RSA_PKCS1_PSS_PADDING);
    }
  }

  static final class Pkcs15 extends RsaEmsa {
    Pkcs15(final AmazonCorrettoCryptoProvider provider) {
      super(provider, RSA_PKCS1_PADDING, Utils.getMdPtr("SHA-256"));
    }
  }
}
