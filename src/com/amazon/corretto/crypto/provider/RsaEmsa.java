// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

class RsaEmsa extends SignatureSpi {
  private final AmazonCorrettoCryptoProvider provider_;
  private EvpKey key_ = null;
  private java.security.Key untranslatedKey_ = null;
  private boolean signMode;
  private PSSParameterSpec pssParams_ = null;
  private long digest_ = 0;
  private long pssMgfMd_ = 0;
  private int pssSaltLen_ = 0;
  private final AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);

  protected RsaEmsa(final AmazonCorrettoCryptoProvider provider) {
    provider_ = provider;
    internalSetParams(PSSParameterSpec.DEFAULT);
  }

  // Required by the provider's EvpService for all Signature classes.
  void setAlgorithmName(final String algorithmName) {}

  private void internalSetParams(final PSSParameterSpec params) {
    if (params == null) {
      pssParams_ = null;
      digest_ = 0;
      pssMgfMd_ = 0;
      pssSaltLen_ = 0;
    } else {
      pssParams_ = params;
      digest_ = Utils.getMdPtr(params.getDigestAlgorithm());
      pssMgfMd_ =
          Utils.getMdPtr(((MGF1ParameterSpec) params.getMGFParameters()).getDigestAlgorithm());
      pssSaltLen_ = params.getSaltLength();
    }
  }

  private void resetBuffer() {
    buffer.reset();
  }

  @Override
  protected synchronized void engineInitSign(final PrivateKey privateKey)
      throws InvalidKeyException {
    if (privateKey == null) {
      throw new InvalidKeyException("Key must not be null");
    }
    if (privateKey.getAlgorithm() == null) {
      throw new InvalidKeyException("Key algorithm must not be null");
    }
    if (untranslatedKey_ != privateKey) {
      if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())
          && !privateKey.getAlgorithm().startsWith("RSA")) {
        throw new InvalidKeyException(
            String.format("Invalid algorithm: %s, expected RSA", privateKey.getAlgorithm()));
      }
      untranslatedKey_ = privateKey;
      if (key_ != null) {
        key_.releaseEphemeral();
      }
      key_ = provider_.translateKey(untranslatedKey_, EvpKeyType.RSA);
    }
    signMode = true;
    resetBuffer();
  }

  @Override
  protected synchronized void engineInitVerify(final PublicKey publicKey)
      throws InvalidKeyException {
    if (publicKey == null) {
      throw new InvalidKeyException("Key must not be null");
    }
    if (publicKey.getAlgorithm() == null) {
      throw new InvalidKeyException("Key algorithm must not be null");
    }
    if (untranslatedKey_ != publicKey) {
      if (!"RSA".equalsIgnoreCase(publicKey.getAlgorithm())
          && !publicKey.getAlgorithm().startsWith("RSA")) {
        throw new InvalidKeyException();
      }
      untranslatedKey_ = publicKey;
      if (key_ != null) {
        key_.releaseEphemeral();
      }
      key_ = provider_.translateKey(untranslatedKey_, EvpKeyType.RSA);
    }
    signMode = false;
    resetBuffer();
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
      resetBuffer();
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
      resetBuffer();
    }
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(final String param) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  @Deprecated
  protected void engineSetParameter(final String param, final Object value)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof PSSParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "Specified parameters supported by this algorithm");
    }
    final PSSParameterSpec pssParams = (PSSParameterSpec) params;
    if (buffer.size() > 0) {
      throw new IllegalStateException(
          "Cannot update PSS parameters with buffered data, reset Signature.");
    }
    if (!"MGF1".equals(pssParams.getMGFAlgorithm())) {
      throw new InvalidAlgorithmParameterException("Invalid PSS MGF algorithm");
    }
    if (pssParams.getTrailerField() != PSSParameterSpec.DEFAULT.getTrailerField()) {
      throw new IllegalArgumentException("Invalid PSS trailer field");
    }
    if (pssParams.getMGFParameters() == null) {
      throw new InvalidAlgorithmParameterException("PSS parameters must specify MGF1 parameters");
    }
    try {
      Utils.getMdPtr(pssParams.getDigestAlgorithm());
      Utils.getMdPtr(((MGF1ParameterSpec) pssParams.getMGFParameters()).getDigestAlgorithm());
    } catch (Exception e) {
      throw new InvalidAlgorithmParameterException();
    }
    final int saltLen = pssParams.getSaltLength();
    final int mdLen = Utils.getMdLen(Utils.getMdPtr(pssParams.getDigestAlgorithm()));
    final int emLen = key_ != null ? (((RSAKey) key_).getModulus().bitLength() + 7) / 8 : 2048 / 8;
    if (saltLen < 0 || saltLen > emLen - mdLen - 2) {
      throw new IllegalArgumentException("PSS salt length invalid");
    }
    internalSetParams(pssParams);
  }

  @Override
  protected synchronized AlgorithmParameters engineGetParameters() {
    if (pssParams_ != null) {
      try {
        final AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS");
        params.init(pssParams_);
        return params;
      } catch (final NoSuchAlgorithmException ex) {
        throw new UnsupportedOperationException("RSASSA-PSS unsupported.", ex);
      } catch (final GeneralSecurityException ex) {
        throw new AssertionError(ex);
      }
    }
    return null;
  }

  private void ensureInitialized(final boolean forSigning) throws SignatureException {
    if (key_ == null) {
      throw new SignatureException("Not initialized");
    }
    if (forSigning != signMode) {
      throw new SignatureException("Incorrect mode for operation");
    }
  }

  private void sniffTest(final byte[] signature, final int offset, final int length)
      throws SignatureException {
    final int expectedLength = (((RSAKey) key_).getModulus().bitLength() + 7) / 8;
    if (length != expectedLength) {
      throw new SignatureException("RSA Signature of invalid length. Expected " + expectedLength);
    }
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

  static final class Pss extends RsaEmsa {
    Pss(final AmazonCorrettoCryptoProvider provider) {
      super(provider);
    }
  }
}
