// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.EMPTY_ARRAY;
import static com.amazon.corretto.crypto.provider.Utils.checkAesKey;
import static com.amazon.corretto.crypto.provider.Utils.checkArrayLimits;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * JCE CipherSpi implementation for AES-GCM-SIV (RFC 8452).
 *
 * <p>AES-GCM-SIV is a nonce-misuse-resistant authenticated encryption scheme. Unlike standard
 * AES-GCM, reusing the same key and nonce combination will only reveal that two plaintexts were
 * identical rather than completely compromising confidentiality.
 *
 * <p>Constraints:
 *
 * <ul>
 *   <li>Nonce must be exactly 12 bytes.
 *   <li>Tag is always 16 bytes (128 bits); other tag lengths are not supported.
 *   <li>Key must be 128 or 256 bits.
 * </ul>
 */
final class AesGcmSivSpi extends CipherSpi {
  static {
    Loader.load();
  }

  /** AES-GCM-SIV nonce length in bytes (fixed per RFC 8452). */
  static final int NONCE_LENGTH_BYTES = 12;

  /** AES-GCM-SIV tag length in bytes (fixed per RFC 8452). */
  static final int TAG_LENGTH_BYTES = 16;

  private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

  private static final int NATIVE_MODE_ENCRYPT = 1;
  private static final int NATIVE_MODE_DECRYPT = 0;

  // -------------------------------------------------------------------
  // Native methods
  // -------------------------------------------------------------------

  /**
   * Creates a native EVP_AEAD_CTX for the given AES key and returns its pointer.
   *
   * @param key AES key bytes (16 or 32 bytes)
   * @return native pointer (must be freed via Utils.releaseEvpAeadCtx)
   */
  static native long nCreateContext(byte[] key);

  /**
   * Encrypts plaintext with AES-GCM-SIV. The output contains ciphertext followed by the 16-byte
   * authentication tag.
   *
   * @param ctxPtr cached EVP_AEAD_CTX pointer (0 if none)
   * @param sameKey true iff the key matches the cached context's key
   * @param ctxOut if non-null, receives the new context pointer for caching
   * @param key AES key bytes
   * @param nonce 12-byte nonce
   * @param input plaintext
   * @param inputOffset offset into input array
   * @param inputLen number of plaintext bytes
   * @param output output buffer (must hold inputLen + 16 bytes from outputOffset)
   * @param outputOffset offset into output array
   * @param aad additional authenticated data (may be null if aadLen == 0)
   * @param aadLen number of AAD bytes
   * @return number of bytes written to output
   */
  private static native int nSeal(
      long ctxPtr,
      boolean sameKey,
      long[] ctxOut,
      byte[] key,
      byte[] nonce,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset,
      byte[] aad,
      int aadLen);

  /**
   * Decrypts and authenticates AES-GCM-SIV ciphertext.
   *
   * @param ctxPtr cached EVP_AEAD_CTX pointer (0 if none)
   * @param sameKey true iff the key matches the cached context's key
   * @param ctxOut if non-null, receives the new context pointer for caching
   * @param key AES key bytes
   * @param nonce 12-byte nonce
   * @param input ciphertext || tag (inputLen must include the 16-byte tag)
   * @param inputOffset offset into input array
   * @param inputLen total input length (ciphertext + 16-byte tag)
   * @param output output buffer for plaintext
   * @param outputOffset offset into output array
   * @param aad additional authenticated data (may be null if aadLen == 0)
   * @param aadLen number of AAD bytes
   * @return number of plaintext bytes written to output
   * @throws AEADBadTagException if authentication fails
   */
  private static native int nOpen(
      long ctxPtr,
      boolean sameKey,
      long[] ctxOut,
      byte[] key,
      byte[] nonce,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset,
      byte[] aad,
      int aadLen)
      throws AEADBadTagException;

  // -------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------

  private final AmazonCorrettoCryptoProvider provider;

  /** Cached native EVP_AEAD_CTX (tied to lastKey). */
  private NativeEvpAeadCtx context = null;

  /**
   * True iff the current key matches the key used to create the cached context. When true, we can
   * pass the cached context pointer directly to nSeal/nOpen.
   */
  private boolean sameKey = false;

  /** The last Key object seen; used to detect same-key reuse. */
  private Key lastKey = null;

  private byte[] nonce;
  private byte[] key;
  private int opMode = -1;

  /** Buffered input for the current operation (used for both encrypt and decrypt). */
  private final AccessibleByteArrayOutputStream inputBuf =
      new AccessibleByteArrayOutputStream(0, Integer.MAX_VALUE);

  /** Buffered AAD. */
  private final AccessibleByteArrayOutputStream aadBuf =
      new AccessibleByteArrayOutputStream(0, Integer.MAX_VALUE);

  private boolean hasConsumedData = false;

  AesGcmSivSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
  }

  private boolean saveNativeContext() {
    switch (provider.getNativeContextReleaseStrategy()) {
      case HYBRID:
        return sameKey;
      case LAZY:
        return true;
      case EAGER:
        return false;
      default:
        throw new AssertionError("This should not be reachable.");
    }
  }

  // -------------------------------------------------------------------
  // CipherSpi overrides
  // -------------------------------------------------------------------

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    if (!"GCM-SIV".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException("Mode must be GCM-SIV");
    }
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    if (!"NoPadding".equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException("AES-GCM-SIV requires NoPadding");
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return 16;
  }

  @Override
  protected int engineGetKeySize(final Key key) throws InvalidKeyException {
    return key.getEncoded().length * 8;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    switch (opMode) {
      case NATIVE_MODE_ENCRYPT:
        return inputBuf.size() + inputLen + TAG_LENGTH_BYTES;
      case NATIVE_MODE_DECRYPT:
        return Math.max(0, inputBuf.size() + inputLen - TAG_LENGTH_BYTES);
      default:
        throw new IllegalStateException("Cipher not initialized");
    }
  }

  @Override
  protected byte[] engineGetIV() {
    return (nonce == null) ? null : nonce.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      final AlgorithmParameters parameters = AlgorithmParameters.getInstance("GCM");
      byte[] nonceForParams = nonce;
      if (nonceForParams == null) {
        nonceForParams = new byte[NONCE_LENGTH_BYTES];
        new LibCryptoRng().nextBytes(nonceForParams);
      }
      parameters.init(new GCMParameterSpec(TAG_LENGTH_BITS, nonceForParams));
      return parameters;
    } catch (final InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new Error("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(final int jceOpMode, final Key key, final SecureRandom secureRandom)
      throws InvalidKeyException {
    if (jceOpMode != Cipher.ENCRYPT_MODE && jceOpMode != Cipher.WRAP_MODE) {
      throw new InvalidKeyException("IV required for AES-GCM-SIV decrypt");
    }

    final byte[] generatedNonce = new byte[NONCE_LENGTH_BYTES];
    secureRandom.nextBytes(generatedNonce);

    try {
      engineInit(
          jceOpMode, key, new GCMParameterSpec(TAG_LENGTH_BITS, generatedNonce), secureRandom);
    } catch (final InvalidAlgorithmParameterException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  protected void engineInit(
      final int jceOpMode,
      final Key key,
      final AlgorithmParameterSpec spec,
      final SecureRandom secureRandom)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final int newOpMode = checkOperation(jceOpMode);
    final byte[] newNonce = checkNonce(spec);
    final byte[] newKey = checkKey(key);

    this.sameKey = (this.key != null) && ConstantTime.equals(this.key, newKey);
    this.opMode = newOpMode;
    this.nonce = newNonce;
    this.key = newKey;
    this.lastKey = key;
    stateReset();
  }

  @Override
  protected void engineInit(
      final int jceOpMode,
      final Key key,
      final AlgorithmParameters algorithmParameters,
      final SecureRandom secureRandom)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    try {
      engineInit(
          jceOpMode,
          key,
          algorithmParameters.getParameterSpec(GCMParameterSpec.class),
          secureRandom);
    } catch (final InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  // -------------------------------------------------------------------
  // Update / AAD
  // -------------------------------------------------------------------

  @Override
  protected byte[] engineUpdate(final byte[] input, final int offset, final int length) {
    // Both encrypt and decrypt buffer; no output is produced until doFinal
    try {
      engineUpdate(input, offset, length, EMPTY_ARRAY, 0);
    } catch (final ShortBufferException e) {
      throw new AssertionError(e);
    }
    return EMPTY_ARRAY;
  }

  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException {
    checkArrayLimits(input, inputOffset, inputLen);
    hasConsumedData = true;
    inputBuf.write(input, inputOffset, inputLen);
    return 0;
  }

  @Override
  protected void engineUpdateAAD(final byte[] bytes, final int offset, final int length) {
    checkArrayLimits(bytes, offset, length);
    if (hasConsumedData) {
      throw new IllegalStateException("AAD cannot be updated after calling update()");
    }
    aadBuf.write(bytes, offset, length);
  }

  @Override
  protected void engineUpdateAAD(final ByteBuffer byteBuffer) {
    if (byteBuffer.hasArray()) {
      engineUpdateAAD(
          byteBuffer.array(),
          byteBuffer.arrayOffset() + byteBuffer.position(),
          byteBuffer.remaining());
    } else {
      final byte[] tmp = new byte[byteBuffer.remaining()];
      byteBuffer.get(tmp);
      engineUpdateAAD(tmp, 0, tmp.length);
    }
    byteBuffer.position(byteBuffer.limit());
  }

  // -------------------------------------------------------------------
  // doFinal
  // -------------------------------------------------------------------

  @Override
  protected byte[] engineDoFinal(final byte[] bytes, final int offset, final int length)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] out = new byte[engineGetOutputSize(length)];
    int actualLen;
    try {
      actualLen = engineDoFinal(bytes, offset, length, out, 0);
    } catch (final ShortBufferException e) {
      throw new AssertionError(e);
    }
    if (actualLen == out.length) {
      return out;
    }
    return Arrays.copyOf(out, actualLen);
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int offset,
      final int length,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    if (opMode == NATIVE_MODE_ENCRYPT) {
      return engineEncryptFinal(input, offset, length, output, outputOffset);
    } else if (opMode == NATIVE_MODE_DECRYPT) {
      return engineDecryptFinal(input, offset, length, output, outputOffset);
    } else {
      throw new IllegalStateException("Cipher not initialized");
    }
  }

  private int engineEncryptFinal(
      byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException {
    if (opMode != NATIVE_MODE_ENCRYPT) {
      throw new IllegalStateException("Cipher not initialized for encryption");
    }
    if (input == null) {
      input = EMPTY_ARRAY;
    }
    checkArrayLimits(input, inputOffset, inputLen);

    final int totalInputLen = inputBuf.size() + inputLen;
    final int requiredOut = totalInputLen + TAG_LENGTH_BYTES;
    if (output.length - outputOffset < requiredOut) {
      throw new ShortBufferException("Output buffer too small: need " + requiredOut + " bytes");
    }

    try {
      // Consolidate buffered + final input
      inputBuf.finalWrite(input, inputOffset, inputLen);
      final byte[] allInput = inputBuf.getDataBuffer();
      final int allInputLen = inputBuf.size();

      final byte[] aad = aadBuf.isEmpty() ? EMPTY_ARRAY : aadBuf.getDataBuffer();
      final int aadLen = aadBuf.size();

      if (context != null) {
        return context.use(
            ptr ->
                nSeal(
                    ptr,
                    sameKey,
                    null,
                    key,
                    nonce,
                    allInput,
                    0,
                    allInputLen,
                    output,
                    outputOffset,
                    aad,
                    aadLen));
      }

      if (saveNativeContext()) {
        final long[] ptrOut = new long[1];
        final int outLen =
            nSeal(
                0,
                false,
                ptrOut,
                key,
                nonce,
                allInput,
                0,
                allInputLen,
                output,
                outputOffset,
                aad,
                aadLen);
        context = new NativeEvpAeadCtx(ptrOut[0]);
        return outLen;
      }

      return nSeal(
          0, false, null, key, nonce, allInput, 0, allInputLen, output, outputOffset, aad, aadLen);
    } finally {
      stateReset();
    }
  }

  private int engineDecryptFinal(
      byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws AEADBadTagException, ShortBufferException {
    if (opMode != NATIVE_MODE_DECRYPT) {
      throw new IllegalStateException("Cipher not initialized for decryption");
    }
    if (input == null) {
      input = EMPTY_ARRAY;
    }
    checkArrayLimits(input, inputOffset, inputLen);

    try {
      inputBuf.finalWrite(input, inputOffset, inputLen);
      final byte[] allInput = inputBuf.getDataBuffer();
      final int allInputLen = inputBuf.size();

      if (allInputLen < TAG_LENGTH_BYTES) {
        throw new AEADBadTagException("Input too short - need tag");
      }

      final int requiredOut = allInputLen - TAG_LENGTH_BYTES;
      if (output.length - outputOffset < requiredOut) {
        throw new ShortBufferException("Output buffer too small: need " + requiredOut + " bytes");
      }

      final byte[] aad = aadBuf.isEmpty() ? EMPTY_ARRAY : aadBuf.getDataBuffer();
      final int aadLen = aadBuf.size();

      if (context != null) {
        return context.use(
            ptr ->
                nOpen(
                    ptr,
                    sameKey,
                    null,
                    key,
                    nonce,
                    allInput,
                    0,
                    allInputLen,
                    output,
                    outputOffset,
                    aad,
                    aadLen));
      }

      if (saveNativeContext()) {
        final long[] ptrOut = new long[1];
        final int outLen =
            nOpen(
                0,
                false,
                ptrOut,
                key,
                nonce,
                allInput,
                0,
                allInputLen,
                output,
                outputOffset,
                aad,
                aadLen);
        context = new NativeEvpAeadCtx(ptrOut[0]);
        return outLen;
      }

      return nOpen(
          0, false, null, key, nonce, allInput, 0, allInputLen, output, outputOffset, aad, aadLen);
    } catch (final AEADBadTagException e) {
      final int fillEnd =
          outputOffset + Math.min(output.length - outputOffset, engineGetOutputSize(inputLen));
      Arrays.fill(output, outputOffset, fillEnd, (byte) 0);
      throw e;
    } finally {
      stateReset();
    }
  }

  // -------------------------------------------------------------------
  // Wrap / Unwrap
  // -------------------------------------------------------------------

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (opMode != NATIVE_MODE_ENCRYPT) {
      throw new IllegalStateException("Cipher must be in WRAP_MODE");
    }
    try {
      final byte[] encoded = Utils.encodeForWrapping(provider, key);
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (final BadPaddingException ex) {
      throw new InvalidKeyException("Wrapping failed", ex);
    }
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (opMode != NATIVE_MODE_DECRYPT) {
      throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
    }
    try {
      final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(provider, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
      throw new InvalidKeyException("Unwrapping failed", ex);
    }
  }

  // -------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------

  private static int checkOperation(final int jceOpMode) throws InvalidAlgorithmParameterException {
    switch (jceOpMode) {
      case Cipher.ENCRYPT_MODE:
      case Cipher.WRAP_MODE:
        return NATIVE_MODE_ENCRYPT;
      case Cipher.DECRYPT_MODE:
      case Cipher.UNWRAP_MODE:
        return NATIVE_MODE_DECRYPT;
      default:
        throw new InvalidAlgorithmParameterException("Unsupported cipher mode " + jceOpMode);
    }
  }

  private static byte[] checkNonce(final AlgorithmParameterSpec spec)
      throws InvalidAlgorithmParameterException {
    final byte[] iv;
    if (spec instanceof GCMParameterSpec) {
      final GCMParameterSpec gcmSpec = (GCMParameterSpec) spec;
      if (gcmSpec.getTLen() != TAG_LENGTH_BITS) {
        throw new InvalidAlgorithmParameterException(
            "AES-GCM-SIV requires a 128-bit tag; got " + gcmSpec.getTLen() + " bits");
      }
      iv = gcmSpec.getIV();
    } else if (spec instanceof IvParameterSpec) {
      iv = ((IvParameterSpec) spec).getIV();
    } else {
      throw new InvalidAlgorithmParameterException(
          "AES-GCM-SIV requires a GCMParameterSpec or IvParameterSpec");
    }
    if (iv == null || iv.length != NONCE_LENGTH_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "AES-GCM-SIV requires a 12-byte nonce; got "
              + (iv == null ? "null" : iv.length + " bytes"));
    }
    return iv.clone();
  }

  private byte[] checkKey(final Key key) throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("Key cannot be null");
    }
    if (key == lastKey && this.key != null) {
      return this.key;
    }
    final byte[] encoded = checkAesKey(key);
    if (encoded.length != 16 && encoded.length != 32) {
      throw new InvalidKeyException(
          "AES-GCM-SIV requires a 128-bit or 256-bit key; got " + (encoded.length * 8) + " bits");
    }
    return encoded;
  }

  private void stateReset() {
    if (context != null && context.isReleased()) {
      context = null;
    }
    inputBuf.reset();
    aadBuf.reset();
    hasConsumedData = false;
  }
}
