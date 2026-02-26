// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;

/**
 * Pre-hashed RSA signature implementation.
 *
 * <p>This class implements RSA signature algorithms that accept a pre-computed message digest
 * instead of the raw message. The caller is responsible for hashing the message with the
 * appropriate digest algorithm before calling {@code update()}.
 *
 * <p>Registered algorithms:
 *
 * <ul>
 *   <li>{@code NONEwithRSASSA-PSS} — Applies RSASSA-PSS padding (RFC 8017 §8.1) to the pre-hashed
 *       digest via {@code RSA_sign_pss_mgf1}/{@code RSA_verify_pss_mgf1}. PSS parameters (hash,
 *       MGF, salt length) are configured via {@link java.security.spec.PSSParameterSpec}.
 *       Interoperable with {@code RSASSA-PSS} when the same parameters and digest are used.
 *       Equivalent to BouncyCastle's {@code NONEwithRSASSA-PSS}.
 * </ul>
 *
 * <p>This is a <b>one-shot</b> algorithm: the complete digest must be provided in a single {@code
 * update()} call. Incremental or byte-by-byte updates are not supported. The digest length must
 * exactly match the output length of the configured hash algorithm.
 *
 * @see java.security.spec.PSSParameterSpec
 */
class NoneWithRsa extends EvpSignatureBase {
  private AccessibleByteArrayOutputStream buffer = new AccessibleByteArrayOutputStream(64, 64);

  protected NoneWithRsa(final AmazonCorrettoCryptoProvider provider, final int paddingType) {
    super(provider, EvpKeyType.RSA, paddingType, 0, false);
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  /**
   * Not supported. This is a one-shot algorithm; the complete digest must be provided in a single
   * call to {@code update(byte[])} or {@code update(ByteBuffer)}.
   *
   * @throws SignatureException always
   */
  @Override
  protected void engineUpdate(final byte b) throws SignatureException {
    throw new SignatureException(
        "Byte-by-byte update not supported. Provide the complete digest in a single update()"
            + " call.");
  }

  /**
   * Provides the pre-computed message digest for signing or verification.
   *
   * <p>This method must be called exactly once with the complete digest. The digest length must
   * match the output length of the configured hash algorithm (validated at sign/verify time).
   *
   * @throws SignatureException if called more than once before sign/verify, or if the provided data
   *     does not match the expected digest length
   */
  @Override
  protected void engineUpdate(final byte[] b, final int off, final int len)
      throws SignatureException {
    if (!isBufferEmpty()) {
      throw new SignatureException(
          "This is a one-shot algorithm. The complete digest must be provided in a single"
              + " update() call.");
    }
    final int expectedDigestLen = Utils.getMdLen(digest_);
    if (len != expectedDigestLen) {
      throw new SignatureException(
          "Input must equal digest length. Expected " + expectedDigestLen + " bytes, got " + len);
    }
    buffer.write(b, off, len);
  }

  /**
   * Provides the pre-computed message digest for signing or verification.
   *
   * <p>This method must be called exactly once with the complete digest. The digest length must
   * match the output length of the configured hash algorithm (validated at sign/verify time).
   *
   * @throws RuntimeException wrapping a {@link SignatureException} if called more than once before
   *     sign/verify, or if the provided data does not match the expected digest length
   */
  @Override
  protected void engineUpdate(final ByteBuffer input) {
    if (!isBufferEmpty()) {
      throw new RuntimeException(
          new SignatureException(
              "This is a one-shot algorithm. The complete digest must be provided in a single"
                  + " update() call."));
    }
    final int expectedDigestLen = Utils.getMdLen(digest_);
    final int len = input.remaining();
    if (len != expectedDigestLen) {
      throw new RuntimeException(
          new SignatureException(
              "Input must equal digest length. Expected "
                  + expectedDigestLen
                  + " bytes, got "
                  + len));
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
              signPss(
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
              verifyPss(
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

  private static native byte[] signPss(
      long privateKey, long hashMd, long mgfMd, int saltLen, byte[] digest, int offset, int length);

  private static native boolean verifyPss(
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

  static final class Pss extends NoneWithRsa {
    Pss(final AmazonCorrettoCryptoProvider provider) {
      super(provider, RSA_PKCS1_PSS_PADDING);
    }
  }
}
