// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

class EvpSignature extends EvpSignatureBase {
  /**
   * Generates a signature in a single pass.
   *
   * @param privateKey a pointer to the private key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the message to be signed
   * @param offset the offset in {@code message} designating the start of the data to be signed.
   * @param length the length of the data in {@code message} to be signed.
   * @return the signature
   * @see {@link PKCS8EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native byte[] sign(
      long privateKey,
      long digestPtr,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length)
      throws SignatureException;

  /**
   * Performs a signature verification in a single pass.
   *
   * @param publicKey a pointer to the public key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the message to be verified
   * @param offset the offset in {@code message} designating the start of the data to be verified.
   * @param length the length of the data in {@code message} to be verified.
   * @param signature the signature to verify
   * @param sigOff the offset in {@code signature} of the actual signature to verify
   * @param sigLen the length of the signatue to verify
   * @return true if the signature was verified. false if not.
   * @see {@link X509EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native boolean verify(
      long publicKey,
      long digestPtr,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length,
      byte[] signature,
      int sigOff,
      int sigLen)
      throws SignatureException;

  /**
   * Starts calculating a signature and returns a native pointer to the context.
   *
   * @param privateKey a pointer to the private key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the start of message to be signed
   * @param offset the offset in {@code message} designating the start of the data to be signed.
   * @param length the length of the data in {@code message} to be signed.
   * @return the context
   * @see {@link PKCS8EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native long signStart(
      long privateKey,
      long digestPtr,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length);

  /**
   * Starts calculating a signature and returns a native pointer to the context.
   *
   * @param privateKey a pointer to the private key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the start of message to be signed. Note that position and limit are ignored.
   * @return the context
   * @see {@link PKCS8EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native long signStartBuffer(
      long privateKey,
      long digestPtr,
      int paddingType,
      long mgfMd,
      int saltLen,
      ByteBuffer message);

  /**
   * Starts verifying a signature and returns a native pointer to the context.
   *
   * @param publicKey a pointer to the public key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the start of message to be verified
   * @param offset the offset in {@code message} designating the start of the data to be verified.
   * @param length the length of the data in {@code message} to be verified.
   * @return the context
   * @see {@link X509EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native long verifyStart(
      long publicKey,
      long digestPtr,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length);

  /**
   * Starts verifying a signature and returns a native pointer to the context.
   *
   * @param publicKey a pointer to the public key
   * @param digestPtr the value from {@link Utils#getEvpMdFromName(String)} representing the digest
   *     to use with this signature
   * @param paddingType the integer defined by OpenSSL as the padding type to be used.
   * @param mgfMd the value from {@link Utils#getEvpMdFromName(String)} used by the Mask Generation
   *     Function (MGF). This parameter is only necessary for RSA-PSS signatures.
   * @param saltLen the length of the salt in bytes. This parameter is only necessary for RSA-PSS
   *     signatures.
   * @param message the start of message to be verified. Note that position and limit are ignored.
   * @return the context
   * @see {@link X509EncodedKeySpec}
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private static native long verifyStartBuffer(
      long publicKey, long digestPtr, int paddingType, long mgfMd, int saltLen, ByteBuffer message);

  /**
   * Updates the context for signing data.
   *
   * @param ctx native context returned by either {@link #signStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #signStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}
   * @param message the message to be signed
   * @param offset the offset in {@code message} designating the start of the data to be verified.
   * @param length the length of the data in {@code message} to be verified.
   */
  private static native void signUpdate(long ctx, byte[] message, int offset, int length);

  /**
   * Updates the context for signing data.
   *
   * @param ctx native context returned by either {@link #signStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #signStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}
   * @param message the message to be signed. Note that position and limit are ignored.
   */
  private static native void signUpdateBuffer(long ctx, ByteBuffer message);

  /**
   * Updates the context for verifying data.
   *
   * @param ctx native context returned by either {@link #verifyStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #verifyStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}
   * @param message the message to be signed
   * @param offset the offset in {@code message} designating the start of the data to be verified.
   * @param length the length of the data in {@code message} to be verified.
   */
  private static native void verifyUpdate(long ctx, byte[] message, int offset, int length);

  /**
   * Updates the context for verifying data.
   *
   * @param ctx native context returned by either {@link #verifyStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #verifyStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}
   * @param message the message to be signed. Note that position and limit are ignored.
   */
  private static native void verifyUpdateBuffer(long ctx, ByteBuffer message);

  /**
   * Calculates the signature and <em>destroys the context</em>.
   *
   * @param ctx native context returned by either {@link #signStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #signStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}.
   */
  private static native byte[] signFinish(long ctx) throws SignatureException;

  /**
   * Verifies the signature and <em>destroys the context</em>.
   *
   * @param ctx native context returned by either {@link #verifyStart(byte[], int, String, int,
   *     String, int, byte[], int, int)} or {@link #verifyStartBuffer(byte[], int, String, int,
   *     String, int, ByteBuffer)}.
   * @param signature the signature to verify
   * @param sigOff the offset in {@code signature} of the actual signature to verify
   * @param sigLen the length of the signatue to verify
   * @return true if the signature was verified. false if not.
   */
  private static native boolean verifyFinish(long ctx, byte[] signature, int sigOff, int sigLen)
      throws SignatureException;

  private byte[] oneByteArray_ = null;
  private InputBuffer<byte[], EvpContext, SignatureException> signingBuffer;
  private InputBuffer<Boolean, EvpContext, SignatureException> verifyingBuffer;

  /**
   * Creates a new instances of this class.
   *
   * @param keyType the keyType as recongized by OpenSSL for this algorithm.
   * @param paddingType the paddingType as recognized by OpenSSL for this algorithm or {@code 0} if
   *     N/A.
   * @param digestName the long digest name as recognized by OpenSSL for this algorithm.
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
   * @see <a
   *     href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
   */
  private EvpSignature(
      AmazonCorrettoCryptoProvider provider,
      final EvpKeyType keyType,
      final int paddingType,
      final String digestName) {
    super(provider, keyType, paddingType, Utils.getMdPtr(digestName));
    Loader.checkNativeLibraryAvailability();

    signingBuffer = getSigningBuffer();
    verifyingBuffer = getVerifyingBuffer();
  }

  private InputBuffer<byte[], EvpContext, SignatureException> getSigningBuffer() {
    return new InputBuffer<byte[], EvpContext, SignatureException>(1024)
        .withInitialUpdater(
            (src, offset, length) ->
                new EvpContext(
                    key_.use(
                        ptr ->
                            signStart(
                                ptr,
                                digest_,
                                paddingType_,
                                pssMgfMd_,
                                pssSaltLen_,
                                src,
                                offset,
                                length))))
        .withInitialUpdater(
            (src) ->
                new EvpContext(
                    key_.use(
                        ptr ->
                            signStartBuffer(
                                ptr, digest_, paddingType_, pssMgfMd_, pssSaltLen_, src))))
        .withUpdater(
            (ctx, src, offset, length) -> ctx.useVoid(ptr -> signUpdate(ptr, src, offset, length)))
        .withUpdater((ctx, src) -> ctx.useVoid(ptr -> signUpdateBuffer(ptr, src)))
        .withDoFinal((ctx) -> signFinish(ctx.take()))
        .withSinglePass(
            (src, offset, length) ->
                key_.use(
                    ptr ->
                        sign(
                            ptr,
                            digest_,
                            paddingType_,
                            pssMgfMd_,
                            pssSaltLen_,
                            src,
                            offset,
                            length)));
  }

  private InputBuffer<Boolean, EvpContext, SignatureException> getVerifyingBuffer() {
    return new InputBuffer<Boolean, EvpContext, SignatureException>(1024)
        .withInitialUpdater(
            (src, offset, length) ->
                new EvpContext(
                    key_.use(
                        ptr ->
                            verifyStart(
                                ptr,
                                digest_,
                                paddingType_,
                                pssMgfMd_,
                                pssSaltLen_,
                                src,
                                offset,
                                length))))
        .withInitialUpdater(
            (src) ->
                new EvpContext(
                    key_.use(
                        ptr ->
                            verifyStartBuffer(
                                ptr, digest_, paddingType_, pssMgfMd_, pssSaltLen_, src))))
        .withUpdater(
            (ctx, src, offset, length) ->
                ctx.useVoid(ptr -> verifyUpdate(ptr, src, offset, length)))
        .withUpdater((ctx, src) -> ctx.useVoid(ptr -> verifyUpdateBuffer(ptr, src)));
    // Both doFinal and SinglePass need to be defined at the very end for verify
    // because they need access to the passed in signature to verify it.
  }

  protected synchronized void engineReset() {
    signingBuffer.reset();
    verifyingBuffer.reset();
  }

  @Override
  protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    super.engineSetParameter(params);
    if (params instanceof PSSParameterSpec) {
      // referesh signing and verifying buffer closures now that we've updated PSS params
      signingBuffer = getSigningBuffer();
      verifyingBuffer = getVerifyingBuffer();
    }
  }

  protected boolean isBufferEmpty() {
    return signingBuffer.size() == 0 && verifyingBuffer.size() == 0;
  }

  @Override
  protected synchronized byte[] engineSign() throws SignatureException {
    ensureInitialized(true);
    try {
      return maybeConvertSignatureToReturn(signingBuffer.doFinal());
    } finally {
      engineReset();
    }
  }

  @Override
  protected synchronized void engineUpdate(final byte val) throws SignatureException {
    ensureInitialized(null);
    if (signMode) {
      signingBuffer.update(val);
    } else {
      verifyingBuffer.update(val);
    }
  }

  @Override
  protected synchronized void engineUpdate(final byte[] src, final int offset, final int length)
      throws SignatureException {
    ensureInitialized(null);
    if (signMode) {
      signingBuffer.update(src, offset, length);
    } else {
      verifyingBuffer.update(src, offset, length);
    }
  }

  @Override
  protected synchronized void engineUpdate(final ByteBuffer input) {
    if (signMode) {
      signingBuffer.update(input);
    } else {
      verifyingBuffer.update(input);
    }
  }

  @Override
  protected synchronized boolean engineVerify(final byte[] sigBytes) throws SignatureException {
    return engineVerify(sigBytes, 0, sigBytes.length);
  }

  @Override
  protected synchronized boolean engineVerify(final byte[] sigBytes, final int off, final int len)
      throws SignatureException {
    ensureInitialized(false);
    try {
      byte[] tempSig = maybeConvertSignatureToVerify(sigBytes, off, len);
      final byte[] finalSigBytes;
      final int finalOff;
      final int finalLen;
      if (tempSig != null) {
        finalSigBytes = tempSig;
        finalOff = 0;
        finalLen = finalSigBytes.length;
      } else {
        finalSigBytes = sigBytes;
        finalOff = off;
        finalLen = len;
      }
      sniffTest(finalSigBytes, finalOff, finalLen);
      return verifyingBuffer
          .withDoFinal((ctx) -> verifyFinish(ctx.take(), finalSigBytes, finalOff, finalLen))
          .withSinglePass(
              (src, offset, length) ->
                  key_.use(
                      ptr ->
                          verify(
                              ptr,
                              digest_,
                              paddingType_,
                              pssMgfMd_,
                              pssSaltLen_,
                              src,
                              offset,
                              length,
                              finalSigBytes,
                              finalOff,
                              finalLen)))
          .doFinal();
    } finally {
      // Clear the handlers which we don't need anymore.
      verifyingBuffer.withDoFinal(null).withSinglePass(null);
      engineReset();
    }
  }

  static final class SHA1withRSA extends EvpSignature {
    SHA1withRSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha1");
    }
  }

  static final class SHA224withRSA extends EvpSignature {
    SHA224withRSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha224");
    }
  }

  static final class SHA256withRSA extends EvpSignature {
    SHA256withRSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha256");
    }
  }

  static final class SHA384withRSA extends EvpSignature {
    SHA384withRSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha384");
    }
  }

  static final class SHA512withRSA extends EvpSignature {
    SHA512withRSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha512");
    }
  }

  static final class RSASSA_PSS extends EvpSignature {
    RSASSA_PSS(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.RSA, RSA_PKCS1_PSS_PADDING, null);
    }
  }

  static final class SHA1withECDSA extends EvpSignature {
    SHA1withECDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0, "sha1");
    }
  }

  static final class SHA224withECDSA extends EvpSignature {
    SHA224withECDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0, "sha224");
    }
  }

  static final class SHA256withECDSA extends EvpSignature {
    SHA256withECDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0, "sha256");
    }
  }

  static final class SHA384withECDSA extends EvpSignature {
    SHA384withECDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0, "sha384");
    }
  }

  static final class SHA512withECDSA extends EvpSignature {
    SHA512withECDSA(final AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.EC, 0, "sha512");
    }
  }
}
