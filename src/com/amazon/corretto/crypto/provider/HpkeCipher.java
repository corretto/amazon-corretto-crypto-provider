// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/** Seals and opens messages in an HPKE base-mode context. */
class HpkeCipher extends CipherSpi {
  static {
    Loader.load();
  }

  private static native long nativeSetupSender(
      int kemId, int kdfId, int aeadId, byte[] recipientPublicKey, byte[] info, byte[] encOut)
      throws InvalidKeyException;

  private static native long nativeSetupRecipient(
      long privateKeyPtr, int kemId, int kdfId, int aeadId, byte[] enc, byte[] info)
      throws InvalidAlgorithmParameterException;

  private static native int nativeSeal(
      long ctxPtr,
      byte[] aad,
      int aadLen,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset);

  private static native int nativeOpen(
      long ctxPtr,
      byte[] aad,
      int aadLen,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset)
      throws AEADBadTagException;

  private static native void nativeFreeContext(long ctxPtr);

  /** Owns a sequence-bearing {@code EVP_HPKE_CTX}; all access requires {@code lock_}. */
  private static final class NativeContext extends NativeResource {
    NativeContext(final long ptr) {
      super(ptr, HpkeCipher::nativeFreeContext, false);
    }
  }

  // Reuse typical buffers; release larger ones after cleansing to avoid retaining peak capacity.
  private static final int RETAINED_CAPACITY = 64 * 1024;

  private static AccessibleByteArrayOutputStream newStream() {
    return new AccessibleByteArrayOutputStream(0, Integer.MAX_VALUE);
  }

  private final Object lock_ = new Object();
  // @GuardedBy("lock_")
  private int mode_;
  // @GuardedBy("lock_")
  private HpkeSuite suite_;
  // @GuardedBy("lock_")
  private NativeContext ctx_;
  // @GuardedBy("lock_") The sender's encapsulation; null for a recipient or before init.
  private byte[] enc_;
  // @GuardedBy("lock_")
  private AccessibleByteArrayOutputStream buffer_ = newStream();
  // @GuardedBy("lock_")
  private AccessibleByteArrayOutputStream aad_ = newStream();
  // @GuardedBy("lock_")
  private boolean dataStarted_;

  HpkeCipher(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
  }

  /**
   * Initializes a fresh HPKE context at sequence number 0. Encryption requires an {@link
   * HpkePublicKey}; decryption requires an undestroyed {@link HpkePrivateKey}. Parameters must be
   * an {@link HpkeParameterSpec} or JDK 26's {@code javax.crypto.spec.HPKEParameterSpec}, naming
   * the key's suite in base mode.
   *
   * <p>The sender's spec must have no encapsulation. Initialization encapsulates immediately, and
   * {@link #engineGetIV()} returns the resulting {@code enc}. The recipient's spec must carry that
   * encapsulation and the same {@code info}. Destroying the private key after successful
   * initialization does not invalidate the recipient context.
   *
   * <p>The {@code random} parameter is ignored; encapsulation draws from AWS-LC's DRBG. Every
   * initialization attempt clears the previous context, buffered input, and AAD.
   *
   * @throws InvalidKeyException if the key has the wrong type, has been destroyed, or is rejected
   *     by AWS-LC
   * @throws InvalidAlgorithmParameterException if parameters are missing or unsupported, the suite
   *     is unavailable or mismatched, or the encapsulation is missing, unexpected, or invalid
   * @throws UnsupportedOperationException if a wrapping mode is requested, checked before suite
   *     support
   */
  @Override
  protected void engineInit(
      final int opmode,
      final Key key,
      final AlgorithmParameterSpec params,
      final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    synchronized (lock_) {
      reset();
      if (key instanceof EvpKemKey) {
        // Public-key import needs no seed; private-key import requires a retained seed.
        throw new InvalidKeyException(
            key instanceof PublicKey
                ? "HPKE requires an HpkePublicKey, not an ML-KEM public key; import the raw ML-KEM"
                    + " public key (the SubjectPublicKeyInfo key bits) with"
                    + " HpkePublicKey.fromEncoded"
                : "HPKE requires an HpkePrivateKey, not an ML-KEM private key; import its 64-byte"
                    + " ML-KEM seed (from a seed-form PKCS#8 encoding, if the key retains its"
                    + " seed) with HpkePrivateKey.fromEncoded");
      }
      if (!(key instanceof HpkeKey)) {
        throw new InvalidKeyException(
            "HPKE requires an HpkePublicKey or HpkePrivateKey, not "
                + (key == null ? "null" : key.getClass().getName()));
      }
      final HpkeParameterSpec spec = HpkeParameterSpec.from(params);
      if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
        throw new UnsupportedOperationException("HPKE supports only ENCRYPT_MODE and DECRYPT_MODE");
      }
      final HpkeSuite suite = HpkeSuite.require(spec.kem_id(), spec.kdf_id(), spec.aead_id());
      final boolean sender = opmode == Cipher.ENCRYPT_MODE;
      if (sender && !(key instanceof HpkePublicKey)) {
        throw new InvalidKeyException("HPKE ENCRYPT_MODE requires the recipient's public key");
      }
      if (!sender && !(key instanceof HpkePrivateKey)) {
        throw new InvalidKeyException("HPKE DECRYPT_MODE requires the recipient's private key");
      }
      if (!sender && ((HpkePrivateKey) key).isDestroyed()) {
        throw new InvalidKeyException("HPKE private key has been destroyed");
      }
      final byte[] enc = spec.encapsulationInternal();
      if (sender && enc != null) {
        throw new InvalidAlgorithmParameterException(
            "HPKE sender spec must not carry an encapsulation");
      }
      if (!sender && enc == null) {
        throw new InvalidAlgorithmParameterException(
            "HPKE recipient spec must carry the sender's encapsulation");
      }
      final HpkeKey hpkeKey = (HpkeKey) key;
      if (hpkeKey.suite() != suite) {
        throw new InvalidAlgorithmParameterException(
            "HPKE key is for suite "
                + HpkeSuite.describe(
                    hpkeKey.suite().kemId, hpkeKey.suite().kdfId, hpkeKey.suite().aeadId)
                + " but the spec names "
                + HpkeSuite.describe(spec.kem_id(), spec.kdf_id(), spec.aead_id()));
      }
      if (!sender && enc.length != suite.encLength()) {
        throw new InvalidAlgorithmParameterException(
            "HPKE encapsulation must be " + suite.encLength() + " bytes for this KEM");
      }
      final byte[] info = spec.infoInternal();
      if (sender) {
        final byte[] newEnc = new byte[suite.encLength()];
        ctx_ =
            wrap(
                nativeSetupSender(
                    suite.kemId,
                    suite.kdfId,
                    suite.aeadId,
                    ((HpkePublicKey) key).getRawPublicKey(),
                    info,
                    newEnc));
        enc_ = newEnc;
      } else {
        // Setup does not retain the key, so later destruction cannot invalidate this context.
        final HpkePrivateKey privateKey = (HpkePrivateKey) key;
        try {
          ctx_ =
              wrap(
                  privateKey.use(
                      ptr ->
                          nativeSetupRecipient(
                              ptr, suite.kemId, suite.kdfId, suite.aeadId, enc, info)));
        } catch (final IllegalStateException ex) {
          // Classify a racing destroy() as an invalid key too.
          if (privateKey.isDestroyed()) {
            throw new InvalidKeyException("HPKE private key has been destroyed", ex);
          }
          throw ex;
        }
      }
      suite_ = suite;
      mode_ = opmode;
    }
  }

  /**
   * Uses sender setup to keep import validation identical to {@code init}.
   *
   * @throws InvalidKeyException if AWS-LC rejects {@code publicKey}
   */
  static void checkPublicKey(final HpkeSuite suite, final byte[] publicKey)
      throws InvalidKeyException {
    nativeFreeContext(
        nativeSetupSender(
            suite.kemId,
            suite.kdfId,
            suite.aeadId,
            publicKey,
            Utils.EMPTY_ARRAY,
            new byte[suite.encLength()]));
  }

  /** Takes ownership of a native context, freeing it if the wrapper cannot be created. */
  private static NativeContext wrap(final long ptr) {
    try {
      return new NativeContext(ptr);
    } catch (final Throwable t) {
      nativeFreeContext(ptr);
      throw t;
    }
  }

  /**
   * Clears the previous context and rejects initialization without an {@code
   * AlgorithmParameterSpec}.
   *
   * @throws InvalidKeyException always
   */
  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    synchronized (lock_) {
      reset();
      throw new InvalidKeyException(
          "An HpkeParameterSpec (or, on JDK 26+, javax.crypto.spec.HPKEParameterSpec) must be"
              + " provided");
    }
  }

  /**
   * Rejects {@code AlgorithmParameters} with the same behavior as {@link #engineInit(int, Key,
   * SecureRandom)}; an {@code AlgorithmParameterSpec} is required.
   *
   * @throws InvalidKeyException always
   */
  @Override
  protected void engineInit(
      final int opmode, final Key key, final AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException {
    engineInit(opmode, key, random);
  }

  // @GuardedBy("lock_")
  private void reset() {
    mode_ = 0;
    suite_ = null;
    if (ctx_ != null) {
      ctx_.release();
      ctx_ = null;
    }
    enc_ = null;
    resetMessage();
  }

  // @GuardedBy("lock_")
  private void resetMessage() {
    // reset() zeroes the used bytes, so a released array holds no message data.
    buffer_.reset();
    aad_.reset();
    if (buffer_.getDataBuffer().length > RETAINED_CAPACITY) {
      buffer_ = newStream();
    }
    if (aad_.getDataBuffer().length > RETAINED_CAPACITY) {
      aad_ = newStream();
    }
    dataStarted_ = false;
  }

  // @GuardedBy("lock_")
  private void assertInitialized() {
    if (mode_ == 0) {
      throw new IllegalStateException("Cipher not initialized");
    }
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    throw new NoSuchAlgorithmException("HPKE does not take a mode");
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("HPKE does not take a padding");
  }

  /** AES-GCM reports its block size, even though HPKE processes whole messages. */
  @Override
  protected int engineGetBlockSize() {
    synchronized (lock_) {
      return mode_ == 0 ? 0 : 16;
    }
  }

  /** Returns the final output size for the buffered input plus {@code inputLen}, excluding enc. */
  @Override
  protected int engineGetOutputSize(final int inputLen) {
    synchronized (lock_) {
      assertInitialized();
      return outputSize(inputLen);
    }
  }

  // @GuardedBy("lock_")
  private int outputSize(final int inputLen) {
    final long total = (long) buffer_.size() + Math.max(0, inputLen);
    final long result =
        mode_ == Cipher.ENCRYPT_MODE
            ? total + suite_.aeadOverhead()
            : Math.max(0, total - suite_.aeadOverhead());
    if (result > Integer.MAX_VALUE) {
      throw new IllegalStateException("HPKE message too large");
    }
    return (int) result;
  }

  /**
   * Returns a defensive copy of the sender's encapsulation, or null before init and for recipients.
   */
  @Override
  protected byte[] engineGetIV() {
    synchronized (lock_) {
      return enc_ == null ? null : enc_.clone();
    }
  }

  /** Returns null; HPKE parameters are supplied only through {@code AlgorithmParameterSpec}. */
  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  /**
   * The size in bits of the key's raw encoding: the encapsulation key for a public key and the
   * 64-byte seed for a private key, so the two keys of one pair report different sizes.
   */
  @Override
  protected int engineGetKeySize(final Key key) throws InvalidKeyException {
    if (key instanceof HpkePublicKey) {
      return 8 * ((HpkePublicKey) key).getRawPublicKey().length;
    }
    if (key instanceof HpkePrivateKey) {
      return 8 * ((HpkePrivateKey) key).suite().privateKeyLength();
    }
    throw new InvalidKeyException("Not an ACCP HPKE key");
  }

  /**
   * Buffers input for the current message without producing output. AWS-LC seals or opens the whole
   * message at finalization, so each message must fit in a Java array.
   *
   * @throws IllegalStateException if the Cipher has not been initialized
   */
  @Override
  protected byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
    synchronized (lock_) {
      buffer(input, inputOffset, inputLen);
      return Utils.EMPTY_ARRAY;
    }
  }

  /**
   * Buffers input as in {@link #engineUpdate(byte[], int, int)}, returning zero without writing to
   * {@code output}.
   */
  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset) {
    synchronized (lock_) {
      buffer(input, inputOffset, inputLen);
      return 0;
    }
  }

  // @GuardedBy("lock_")
  private void buffer(final byte[] input, final int inputOffset, final int inputLen) {
    assertInitialized();
    if (input == null || inputLen == 0) {
      return;
    }
    buffer_.write(input, inputOffset, inputLen);
    dataStarted_ = true;
  }

  /**
   * Buffers AAD for the current message. Supply all AAD before buffering message data with {@code
   * update}.
   *
   * @throws IllegalStateException if the Cipher is uninitialized or message data has already been
   *     buffered
   */
  @Override
  protected void engineUpdateAAD(final byte[] src, final int offset, final int len) {
    synchronized (lock_) {
      checkAadAllowed();
      aad_.write(src, offset, len);
    }
  }

  /** Buffers AAD as in {@link #engineUpdateAAD(byte[], int, int)}, consuming {@code src}. */
  @Override
  protected void engineUpdateAAD(final ByteBuffer src) {
    synchronized (lock_) {
      checkAadAllowed();
      aad_.write(src);
    }
  }

  // @GuardedBy("lock_")
  private void checkAadAllowed() {
    assertInitialized();
    if (dataStarted_) {
      throw new IllegalStateException("updateAAD must be called before update for each message");
    }
  }

  /**
   * Seals or opens the current message, combining buffered input with {@code input}, and returns an
   * exactly sized array. Encryption returns only the AEAD ciphertext, including its 16-byte tag; it
   * does not include the encapsulation.
   *
   * <p>Success advances the context's sequence number. Subsequent calls process the next message,
   * so recipients must open messages in the order they were sealed.
   *
   * <p>A failed open leaves the sequence number unchanged. Buffered input and AAD are cleared after
   * either success or a failed open; retry a failed open with the intact message and supply its AAD
   * again.
   *
   * @throws AEADBadTagException with message {@code "HPKE decryption failed"} if the ciphertext
   *     does not open, including if it is shorter than the tag
   * @throws IllegalStateException if the Cipher is uninitialized or the message is too large
   */
  @Override
  protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    synchronized (lock_) {
      assertInitialized();
      final int len = input == null ? 0 : inputLen;
      final byte[] output = new byte[outputSize(len)];
      try {
        final int written = doFinal(input, inputOffset, len, output, 0);
        if (written != output.length) {
          throw new RuntimeCryptoException("Unexpected HPKE output length");
        }
        return output;
      } catch (final ShortBufferException ex) {
        throw new RuntimeCryptoException("Unexpected short buffer", ex);
      }
    }
  }

  /**
   * Seals or opens a message as in {@link #engineDoFinal(byte[], int, int)}, writing the result to
   * {@code output} and returning the number of bytes written.
   *
   * <p>A failed open zeroes the output range, including any overlapping ciphertext. Keep a separate
   * intact copy of the message for retries.
   *
   * @throws ShortBufferException if output space is insufficient; the sequence number, buffered
   *     input, and AAD remain unchanged, allowing a retry with the same input and a larger buffer
   */
  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    synchronized (lock_) {
      assertInitialized();
      return doFinal(input, inputOffset, input == null ? 0 : inputLen, output, outputOffset);
    }
  }

  // @GuardedBy("lock_")
  private int doFinal(
      byte[] input, int inputOffset, int inputLen, final byte[] output, final int outputOffset)
      throws ShortBufferException, AEADBadTagException {
    if (input == null) {
      input = Utils.EMPTY_ARRAY;
      inputOffset = 0;
      inputLen = 0;
    }
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    // Check capacity first so a short-buffer retry preserves the sequence, buffered input and AAD.
    final int needed = outputSize(inputLen);
    if (output == null || outputOffset < 0 || output.length - outputOffset < needed) {
      throw new ShortBufferException("Need " + needed + " bytes of output space");
    }
    byte[] temp = null;
    try {
      if (!buffer_.isEmpty()) {
        buffer_.finalWrite(input, inputOffset, inputLen);
        input = buffer_.getDataBuffer();
        inputOffset = 0;
        inputLen = buffer_.size();
      }
      final boolean sender = mode_ == Cipher.ENCRYPT_MODE;
      if (!sender && inputLen < suite_.aeadOverhead()) {
        throw new AEADBadTagException("HPKE decryption failed");
      }
      // AWS-LC allows exact in-place or disjoint output. Copy other overlaps and cleanse
      // afterwards.
      if (input == output
          && inputOffset != outputOffset
          && inputOffset < outputOffset + needed
          && outputOffset < inputOffset + inputLen) {
        temp = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        input = temp;
        inputOffset = 0;
      }
      final byte[] aad = aad_.getDataBuffer();
      final int aadLen = aad_.size();
      final byte[] in = input;
      final int inOff = inputOffset;
      final int inLen = inputLen;
      if (sender) {
        return ctx_.use(
            ptr -> nativeSeal(ptr, aad, aadLen, in, inOff, inLen, output, outputOffset));
      }
      return ctx_.use(ptr -> nativeOpen(ptr, aad, aadLen, in, inOff, inLen, output, outputOffset));
    } finally {
      // Buffered input and AAD apply to one message only, whether or not it succeeded.
      resetMessage();
      if (temp != null) {
        Arrays.fill(temp, (byte) 0);
      }
    }
  }
}
