// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Pre-hashed RSA signature implementation (RFC 8017).
 *
 * <p>This class implements RSA signature schemes that accept a pre-computed message digest instead
 * of the raw message. The caller is responsible for hashing the message with the appropriate digest
 * algorithm before calling {@code update()}.
 *
 * <p>This is a <b>one-shot</b> algorithm: the complete digest must be provided in a single {@code
 * update()} call. Incremental or byte-by-byte updates are not supported. The digest length must
 * exactly match the output length of the configured hash algorithm.
 *
 * <p>Registered algorithms:
 *
 * <ul>
 *   <li>{@code NONEwithRSASSA-PSS} -- Applies RSASSA-PSS padding (RFC 8017 Sec. 8.1) to the
 *       pre-hashed digest via {@code RSA_sign_pss_mgf1}/{@code RSA_verify_pss_mgf1}. PSS parameters
 *       (hash, MGF, salt length) are configured via {@link PSSParameterSpec}. Interoperable with
 *       {@code RSASSA-PSS} when the same parameters and digest are used. Equivalent to
 *       BouncyCastle's {@code NONEwithRSASSA-PSS}.
 *   <li>{@code NONEwithRSA} -- Applies RSASSA-PKCS1-v1_5 padding (RFC 8017 Sec. 8.2) to the
 *       caller-supplied bytes via {@code RSA_sign_raw}/{@code RSA_verify_raw}. Accepts any input up
 *       to {@code rsaSize - 11} bytes (the PKCS#1 v1.5 padding overhead). No DigestInfo wrapping is
 *       performed; the raw bytes are signed directly. {@code setParameter} is not supported (throws
 *       {@code UnsupportedOperationException}). Interoperable with SunJCE and BouncyCastle {@code
 *       NONEwithRSA} implementations.
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017">RFC 8017: PKCS #1</a>
 * @see PSSParameterSpec
 */
class NoneWithRsa extends EvpSignatureBase {
  private final AccessibleByteArrayOutputStream buffer = new AccessibleByteArrayOutputStream();

  protected NoneWithRsa(final AmazonCorrettoCryptoProvider provider, final int paddingType) {
    super(provider, EvpKeyType.RSA, paddingType, 0, false);
  }

  protected NoneWithRsa(
      final AmazonCorrettoCryptoProvider provider, final int paddingType, final long digest) {
    super(provider, EvpKeyType.RSA, paddingType, digest, false);
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  /**
   * Not supported. This is a one-shot signature scheme; use {@link #engineUpdate(byte[], int, int)}
   * to supply the complete digest in a single call.
   */
  @Override
  protected void engineUpdate(final byte b) throws SignatureException {
    throw new SignatureException(
        "One-shot signature: supply the complete digest via update(byte[], int, int)");
  }

  /**
   * Provides the pre-computed message digest for signing or verification.
   *
   * <p>This method must be called exactly once. For {@code NONEwithRSASSA-PSS}, the input length
   * must match the configured hash algorithm's output length. For {@code NONEwithRSA}, any length
   * up to {@code rsaSize - 11} bytes is accepted.
   *
   * @throws SignatureException if called more than once before sign/verify, or if the provided data
   *     does not match the expected digest length (PSS only)
   */
  @Override
  protected void engineUpdate(final byte[] b, final int off, final int len)
      throws SignatureException {
    if (!isBufferEmpty()) {
      throw new SignatureException("Digest already provided; one-shot signature allows one update");
    }
    if (paddingType_ == RSA_PKCS1_PSS_PADDING) {
      final int expectedDigestLen = Utils.getMdLen(digest_);
      if (len != expectedDigestLen) {
        throw new SignatureException(
            "Input must equal digest length. Expected " + expectedDigestLen + " bytes, got " + len);
      }
    }
    buffer.write(b, off, len);
  }

  /**
   * Provides the pre-computed message digest for signing or verification.
   *
   * <p>This method must be called exactly once. For {@code NONEwithRSASSA-PSS}, the input length
   * must match the configured hash algorithm's output length. For {@code NONEwithRSA}, any length
   * up to {@code rsaSize - 11} bytes is accepted.
   *
   * @throws RuntimeException wrapping a {@link SignatureException} if called more than once before
   *     sign/verify, or if the provided data does not match the expected digest length (PSS only)
   */
  @Override
  protected void engineUpdate(final ByteBuffer input) {
    if (!isBufferEmpty()) {
      throw new RuntimeException(
          new SignatureException("Digest already provided; one-shot signature allows one update"));
    }
    if (paddingType_ == RSA_PKCS1_PSS_PADDING) {
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
    }
    buffer.write(input);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    try {
      ensureInitialized(true);
      if (isBufferEmpty()) {
        throw new SignatureException("No digest provided. Call update() before sign().");
      }
      return key_.use(
          ptr ->
              sign(
                  ptr,
                  digest_,
                  paddingType_,
                  pssMgfMd_,
                  pssSaltLen_,
                  buffer.getDataBuffer(),
                  0,
                  buffer.size()));
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
      if (isBufferEmpty()) {
        throw new SignatureException("No digest provided. Call update() before verify().");
      }
      sniffTest(sigBytes, offset, length);
      return key_.use(
          ptr ->
              verify(
                  ptr,
                  digest_,
                  paddingType_,
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

  /**
   * Sets algorithm parameters.
   *
   * <p>For {@code NONEwithRSASSA-PSS}, delegates to {@link EvpSignatureBase} which fully validates
   * and applies all PSS parameters (digest, MGF, salt length, trailer).
   *
   * @throws InvalidAlgorithmParameterException if the parameter type is not supported or the digest
   *     algorithm is unrecognized
   * @throws IllegalStateException if called while the buffer contains data
   */
  @Override
  protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (paddingType_ == RSA_PKCS1_PSS_PADDING) {
      if (!(params instanceof PSSParameterSpec)) {
        throw new InvalidAlgorithmParameterException(
            "Only PSSParameterSpec is accepted for NONEwithRSASSA-PSS");
      }
      if (!isBufferEmpty()) {
        throw new IllegalStateException(
            "Cannot update parameters with buffered data, reset Signature.");
      }
      final PSSParameterSpec pssParams = (PSSParameterSpec) params;
      try {
        digest_ = Utils.getMdPtr(pssParams.getDigestAlgorithm());
      } catch (Exception e) {
        throw new InvalidAlgorithmParameterException(
            "Unsupported digest: " + pssParams.getDigestAlgorithm());
      }
      super.engineSetParameter(pssParams);
      return;
    }
    throw new UnsupportedOperationException("setParameter is not supported for NONEwithRSA");
  }

  @Override
  protected synchronized AlgorithmParameters engineGetParameters() {
    if (paddingType_ == RSA_PKCS1_PADDING) {
      return null;
    }
    return super.engineGetParameters();
  }

  private static native byte[] sign(
      long privateKey,
      long hashMd,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] digest,
      int offset,
      int length);

  private static native boolean verify(
      long publicKey,
      long hashMd,
      int paddingType,
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

  static final class Pkcs15 extends NoneWithRsa {
    Pkcs15(final AmazonCorrettoCryptoProvider provider) {
      super(provider, RSA_PKCS1_PADDING, Utils.getMdPtr("SHA-256"));
    }
  }
}
