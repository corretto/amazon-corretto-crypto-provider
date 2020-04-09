// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class EvpSignature extends EvpSignatureBase {
    /** The number a times a key must be reused prior to keeping it in native memory rather than freeing it each time. **/
    private static final int KEY_REUSE_THRESHOLD = 1;

    /**
     * Generates a signature in a single pass.
     *
     * @param privateKey
     *            a DER PKCS8 encoded private key appropriate to the algorithm.
     * @param ctxHandle
     *            an optional single-element array containing a native pointer to a.
     *            @{link EvpContext}. If this is @{code null}, then it is ignored. If it is non-null and equal
     *            to 0, then a new EVP_PKEY is allocated and the pointer is stored in the array. If
     *            it is non-null and non-zero, then it is used as a valid handle.
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param checkPrivateKey
     *            run extra consistency checks on the private key if possible
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the message to be signed
     * @param offset
     *            the offset in {@code message} designating the start of the data to be signed.
     * @param length
     *            the length of the data in {@code message} to be signed.
     * @return the signature
     *
     * @see {@link PKCS8EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native byte[] sign(byte[] privateKey, long[] ctxHandle, int keyType, boolean checkPrivateKey, String digestName, int paddingType, String mgfMd,
            int saltLen, byte[] message, int offset, int length);


    /**
     * Performs a signature verification in a single pass.
     *
     * @param publicKey
     *            a DER X509 encoded public key appropriate to the algorithm.
     * @param ctxHandle
     *            an optional single-element array containing a native pointer to a.
     *            @{link EvpContext}. If this is @{code null}, then it is ignored. If it is non-null and equal
     *            to 0, then a new EVP_PKEY is allocated and the pointer is stored in the array. If
     *            it is non-null and non-zero, then it is used as a valid handle. 
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the message to be verified
     * @param offset
     *            the offset in {@code message} designating the start of the data to be verified.
     * @param length
     *            the length of the data in {@code message} to be verified.
     * @param signature
     *            the signature to verify
     * @param sigOff
     *            the offset in {@code signature} of the actual signature to verify
     * @param sigLen
     *            the length of the signatue to verify
     * @return true if the signature was verified. false if not.
     *
     * @see {@link X509EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native boolean verify(byte[] publicKey, long[] ctxHandle, int keyType, String digestName, int paddingType,
            String mgfMd, int saltLen, byte[] message, int offset, int length, byte[] signature, int sigOff, int sigLen);

    /**
     * Starts calculating a signature and returns a native pointer to the context.
     *
     * @param privateKey
     *            a DER PKCS8 encoded private key appropriate to the algorithm.
     * @param ctxHandle
     *            if non-zero, this is treated as a native pointer to a
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param checkPrivateKey
     *            run extra consistency checks on the private key if possible
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the start of message to be signed
     * @param offset
     *            the offset in {@code message} designating the start of the data to be signed.
     * @param length
     *            the length of the data in {@code message} to be signed.
     * @return the context
     *
     * @see {@link PKCS8EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native long signStart(byte[] privateKey, long ctxHandle, int keyType, boolean checkPrivateKey, String digestName, int paddingType,
            String mgfMd, int saltLen, byte[] message, int offset, int length);

    /**
     * Starts calculating a signature and returns a native pointer to the context.
     *
     * @param privateKey
     *            a DER PKCS8 encoded private key appropriate to the algorithm.
     * @param ctxHandle
     *            if non-zero, this is treated as a native pointer to an @{link EvpContext}
     *            associated with the current key.
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param checkPrivateKey
     *            run extra consistency checks on the private key if possible
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the start of message to be signed. Note that position and limit are ignored.
     * @return the context
     *
     * @see {@link PKCS8EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native long signStartBuffer(byte[] privateKey, long ctxHandle, int keyType, boolean checkPrivateKey, String digestName, int paddingType,
            String mgfMd, int saltLen, ByteBuffer message);

    /**
     * Starts verifying a signature and returns a native pointer to the context.
     *
     * @param publicKey
     *            a DER X509 encoded public key appropriate to the algorithm.
     * @param ctxHandle
     *            if non-zero, this is treated as a native pointer to an @{link EvpContext}
     *            associated with the current key.
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the start of message to be verified
     * @param offset
     *            the offset in {@code message} designating the start of the data to be verified.
     * @param length
     *            the length of the data in {@code message} to be verified.
     * @return the context
     *
     * @see {@link X509EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native long verifyStart(byte[] publicKey, long ctxHandle, int keyType, String digestName, int paddingType,
            String mgfMd, int saltLen, byte[] message, int offset, int length);

    /**
     * Starts verifying a signature and returns a native pointer to the context.
     *
     * @param publicKey
     *            a DER X509 encoded public key appropriate to the algorithm.
     * @param ctxHandle
     *            if non-zero, this is treated as a native pointer to an @{link EvpContext}
     *            associated with the current key.
     * @param keyType
     *            the integer defined by OpenSSL as the key type of the {@code privateKey}
     * @param digestName
     *            the "long name" of the digest (as defined by OpenSSL) used by the signature.
     * @param paddingType
     *            the integer defined by OpenSSL as the padding type to be used.
     * @param mgfMd
     *            the the "long name" of the digest (as defined by OpenSSL) used by the Mask
     *            Generation Function (MGF). This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param saltLen
     *            the length of the salt in bytes. This parameter is only necessary for RSA-PSS
     *            signatures.
     * @param message
     *            the start of message to be verified. Note that position and limit are ignored.
     * @return the context
     *
     * @see {@link X509EncodedKeySpec}
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private static native long verifyStartBuffer(byte[] publicKey, long ctxHandle, int keyType, String digestName, int paddingType,
            String mgfMd, int saltLen, ByteBuffer message);

    /**
     * Updates the context for signing data.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #signStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #signStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}
     * @param message
     *            the message to be signed
     * @param offset
     *            the offset in {@code message} designating the start of the data to be verified.
     * @param length
     *            the length of the data in {@code message} to be verified.
     */
    private static native void signUpdate(long ctx, byte[] message, int offset, int length);

    /**
     * Updates the context for signing data.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #signStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #signStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}
     * @param message
     *            the message to be signed. Note that position and limit are ignored.
     */
    private static native void signUpdateBuffer(long ctx, ByteBuffer message);

    /**
     * Updates the context for verifying data.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #verifyStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #verifyStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}
     * @param message
     *            the message to be signed
     * @param offset
     *            the offset in {@code message} designating the start of the data to be verified.
     * @param length
     *            the length of the data in {@code message} to be verified.
     */
    private static native void verifyUpdate(long ctx, byte[] message, int offset, int length);

    /**
     * Updates the context for verifying data.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #verifyStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #verifyStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}
     * @param message
     *            the message to be signed. Note that position and limit are ignored.
     */
    private static native void verifyUpdateBuffer(long ctx, ByteBuffer message);

    /**
     * Calculates the signature and <em>destroys the context</em>.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #signStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #signStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}.
     * @param preserveCtx
     *            if true indicates that the context should be preserved rather than destroyed.
     * @return the signature
     */
    private static native byte[] signFinish(long ctx, boolean preserveCtx);

    /**
     * Verifies the signature and <em>destroys the context</em>.
     *
     * @param ctx
     *            native context returned by either
     *            {@link #verifyStart(byte[], int, String, int, String, int, byte[], int, int)} or
     *            {@link #verifyStartBuffer(byte[], int, String, int, String, int, ByteBuffer)}.
     * @param signature
     *            the signature to verify
     * @param sigOff
     *            the offset in {@code signature} of the actual signature to verify
     * @param sigLen
     *            the length of the signatue to verify
     * @param preserveCtx
     *            if true indicates that the context should be preserved rather than destroyed.
     * @return true if the signature was verified. false if not.
     */
    private static native boolean verifyFinish(long ctx, byte[] signature, int sigOff, int sigLen, boolean preserveCtx);

    private final AmazonCorrettoCryptoProvider provider_;
    private final String digestName_;
    private final byte[] oneByteArray_ = new byte[1];
    private final InputBuffer<byte[], Void> signingBuffer;
    private final InputBuffer<Boolean, Void> verifyingBuffer;

    /**
     * Creates a new instances of this class.
     * @param keyType the keyType as recongized by OpenSSL for this algorithm. 
     * @param paddingType the paddingType as recognized by OpenSSL for this algorithm or {@code 0} if N/A.
     * @param digestName the long digest name as recognized by OpenSSL for this algorithm.
     * 
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_rsa_padding.html">EVP_PKEY_CTX_ctrl</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_base_id.html">EVP_PKEY_base_id</a>
     * @see <a
     *      href="https://www.openssl.org/docs/man1.1.0/crypto/EVP_get_digestbyname.html">EVP_get_digestbyname</a>
     */
    private EvpSignature(AmazonCorrettoCryptoProvider provider, final EvpKeyType keyType, final int paddingType, final String digestName) {
        super(keyType, paddingType);
        Loader.checkNativeLibraryAvailability();
        provider_ = provider;
        digestName_ = digestName;

        signingBuffer = new InputBuffer<byte[], Void>(1024)
                .withInitialUpdater((src, offset, length) -> {
                        if (ctx_ == null) {
                            ctx_ = new EvpContext(signStart(keyDer_, 0, keyType_.nativeValue,
                                provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                                digestName_, paddingType_, null, 0,
                                src, offset, length));
                        } else {
                            ctx_.use(c -> signStart(keyDer_, c, keyType_.nativeValue,
                                provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                                digestName_, paddingType_, null, 0,
                                src, offset, length));
                        }
                        return null;
                })
                .withInitialUpdater((src) -> {
                    if (ctx_ == null) {
                        ctx_ = new EvpContext(signStartBuffer(keyDer_, 0, keyType_.nativeValue,
                            provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                            digestName_, paddingType_, null, 0, src));
                    } else {
                        ctx_.use(c -> signStartBuffer(keyDer_, c, keyType_.nativeValue,
                            provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                            digestName_, paddingType_, null, 0, src));
                    }
                    return null;
                })
                .withUpdater((ignored, src, offset, length) -> {
                    ctx_.useVoid(ptr -> signUpdate(ptr, src, offset, length));
                })
                .withUpdater((ignored, src) -> {
                    ctx_.useVoid(ptr -> signUpdateBuffer(ptr, src));
                })
                .withDoFinal((ignored) -> {
                        final byte[] result;
                        if (keyUsageCount_ > KEY_REUSE_THRESHOLD) {
                            result = ctx_.use(c -> signFinish(c, true));
                        } else {
                            try {
                                result = signFinish(ctx_.take(), false);
                            } finally {
                                ctx_ = null;
                            }
                        }
                        keyUsageCount_++;
                        return result;
                })
                .withSinglePass((src, offset, length) -> {
                        final byte[] result;
                        if (ctx_ != null) {
                            result = ctx_.use(c -> sign(keyDer_, new long[] {c}, keyType_.nativeValue,
                                provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                                digestName_, paddingType, null, 0,
                                  src, offset, length));
                        } else {
                          long[] handle = keyUsageCount_ > KEY_REUSE_THRESHOLD ? new long[1] : null;
                          result = sign(keyDer_, handle, keyType_.nativeValue,
                              provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
                              digestName_, paddingType, null, 0,
                              src, offset, length);
                          if (handle != null) {
                            ctx_ = new EvpContext(handle[0]);
                          }
                        }
                        keyUsageCount_++;
                        return result;
                });
        verifyingBuffer = new InputBuffer<Boolean, Void>(1024)
                .withInitialUpdater((src, offset, length) -> {
                  if (ctx_ != null) {
                    ctx_.use(c -> verifyStart(keyDer_, c, keyType_.nativeValue, digestName_,
                        paddingType_, null, 0,
                        src, offset, length));
                  } else {
                    ctx_ = new EvpContext(verifyStart(keyDer_, 0, keyType_.nativeValue, digestName_,
                        paddingType_, null, 0,
                        src, offset, length));
                  }
                  return null;
                })
                .withInitialUpdater((src) -> {
                  if (ctx_ != null) {
                    ctx_.use(c -> verifyStartBuffer(keyDer_, c, keyType_.nativeValue,
                        digestName_, paddingType_, null, 0, src));
                  } else {
                    ctx_ = new EvpContext(verifyStartBuffer(keyDer_, 0, keyType_.nativeValue,
                        digestName_, paddingType_, null, 0, src));
                  }
                  return null;
                })
                .withUpdater((ignored, src, offset, length) -> {
                    ctx_.useVoid(ptr -> verifyUpdate(ptr, src, offset, length));
                })
                .withUpdater((ignored, src) -> {
                  ctx_.useVoid(ptr -> verifyUpdateBuffer(ptr, src));
                });
        // Both doFinal and SinglePass need to be defined at the very end for verify
        // because they need access to the passed in signature to verify it.
    }

    protected synchronized void engineReset() {
        signingBuffer.reset();
        verifyingBuffer.reset();
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
        oneByteArray_[0] = val;
        engineUpdate(oneByteArray_, 0, 1);
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
    protected synchronized boolean engineVerify(byte[] sigBytes, int off, int len)
            throws SignatureException {
        ensureInitialized(false);
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
        try {
            return verifyingBuffer
                .withDoFinal((ignored) -> {
                    final boolean result;
                    if (keyUsageCount_ > KEY_REUSE_THRESHOLD) {
                      result = ctx_.use(c -> verifyFinish(c, finalSigBytes, finalOff, finalLen, true));
                    } else {
                      try {
                        result = verifyFinish(ctx_.take(), finalSigBytes, finalOff, finalLen, false);
                      } finally {
                        ctx_ = null;
                      }
                    }
                    keyUsageCount_++;
                    return result;
                })
                .withSinglePass((src, offset, length) -> {
                  final boolean result;
                  if (ctx_ != null) {
                    result = ctx_.use(c -> verify(keyDer_, new long[]{c}, keyType_.nativeValue,
                            digestName_, paddingType_, null, 0,
                            src, offset, length, finalSigBytes, finalOff, finalLen));
                  } else {
                    final long[] handle = keyUsageCount_ > KEY_REUSE_THRESHOLD ? new long[1] : null;
                    result = verify(keyDer_, handle, keyType_.nativeValue,
                        digestName_, paddingType_, null, 0,
                        src, offset, length, finalSigBytes, finalOff, finalLen);
                    if (handle != null) {
                      ctx_ = new EvpContext(handle[0]);
                    }
                  }
                  keyUsageCount_++;
                  return result;
                })
                .doFinal();
        } finally {
            // Clear the handlers which we don't need anymore.
            verifyingBuffer.withDoFinal(null).withSinglePass(null);
            engineReset();
        }
    }

    static final class SHA1withRSA extends EvpSignature {
        SHA1withRSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha1");
        }
    }

    static final class SHA224withRSA extends EvpSignature {
        SHA224withRSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha224");
        }
    }

    static final class SHA256withRSA extends EvpSignature {
        SHA256withRSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha256");
        }
    }

    static final class SHA384withRSA extends EvpSignature {
        SHA384withRSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha384");
        }
    }

    static final class SHA512withRSA extends EvpSignature {
        SHA512withRSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.RSA, RSA_PKCS1_PADDING, "sha512");
        }
    }

    static final class SHA1withECDSA extends EvpSignature {
        SHA1withECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0, "sha1");
        }
    }

    static final class SHA224withECDSA extends EvpSignature {
        SHA224withECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0, "sha224");
        }
    }

    static final class SHA256withECDSA extends EvpSignature {
        SHA256withECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0, "sha256");
        }
    }

    static final class SHA384withECDSA extends EvpSignature {
        SHA384withECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0, "sha384");
        }
    }

    static final class SHA512withECDSA extends EvpSignature {
        SHA512withECDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.EC, 0, "sha512");
        }
    }

    static final class SHA1withDSA extends EvpSignature {
        SHA1withDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0, "sha1");
        }
    }

    static final class SHA224withDSA extends EvpSignature {
        SHA224withDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0, "sha224");
        }
    }

    static final class SHA256withDSA extends EvpSignature {
        SHA256withDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0, "sha256");
        }
    }

    static final class SHA384withDSA extends EvpSignature {
        SHA384withDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0, "sha384");
        }
    }

    static final class SHA512withDSA extends EvpSignature {
        SHA512withDSA(AmazonCorrettoCryptoProvider provider) {
            super(provider, EvpKeyType.DSA, 0, "sha512");
        }
    }
}
