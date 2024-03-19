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

final class AesGcmSpi extends CipherSpi {
  static {
    Loader.load();
  }

  private static final int DEFAULT_TAG_LENGTH = 16 * 8;
  private static final int DEFAULT_IV_LENGTH_BYTES = 12;

  /* Some random notes:
   * For decrypt mode, we buffer all data and process the decryption in doFinal;
   * this is because we cannot safely return only plaintext until we have validated
   * the tag at the end of the ciphertext.
   * Additionally, this matches JCE behavior.
   */

  private static final int NATIVE_MODE_ENCRYPT = 1;
  private static final int NATIVE_MODE_DECRYPT = 0;

  /**
   * Performs an encryption operation in a single call. AAD data is not supported in this mode. The
   * native-side code will take care of periodically dropping any buffer locks it has to allow GC to
   * make progress.
   *
   * @param ctxPtr Optional Context pointer
   * @param ctxPtrOut Optional out parameter to recieve new context
   * @param input Input plaintext to encrypt
   * @param inputOffset Offset within input array of start of plaintext
   * @param inputLength Data length to encrypt
   * @param result Result array - must have room for inputLength + tagLen + resultOffset bytes
   * @param resultOffset Offset of start of ciphertext in result array
   * @param tagLen Length of GCM tag
   * @param key AES key
   * @param iv Initialization vector
   * @return Actual number of bytes written
   */
  private static native int oneShotEncrypt(
      long ctxPtr,
      boolean sameKey,
      long[] ctxPtrOut,
      byte[] input,
      int inputOffset,
      int inputLength,
      byte[] result,
      int resultOffset,
      int tagLen,
      byte[] key,
      byte[] iv);

  /**
   * Performs a decryption operation in a single call. Unlike oneShotEncrypt, AAD mode is supported.
   * The native-side code will take care of periodically dropping any buffer locks it has to allow
   * GC to make progress.
   *
   * @param ctxPtr Optional Context pointer
   * @param ctxPtrOut Optional out parameter to recieve new context
   * @param input Input plaintext to encrypt
   * @param inoffset Offset within input array of start of plaintext
   * @param inlen Data length to encrypt
   * @param result Result array - must have room for inputLength + tagLen + resultOffset bytes
   * @param resultOffset Offset of start of ciphertext in result array
   * @param tagLen Length of GCM tag
   * @param key AES key
   * @param iv Initialization vector
   * @param aadBuffer AAD data buffer; the data must start from offset zero in this buffer
   * @param aadSize Size of AAD data; any data in the buffer beyond this point is ignored
   * @return Actual number of bytes written
   */
  private static native int oneShotDecrypt(
      long ctxPtr,
      boolean sameKey,
      long[] ctxPtrOut,
      byte[] input,
      int inoffset,
      int inlen,
      byte[] result,
      int resultOffset,
      int tagLen,
      byte[] key,
      byte[] iv,
      byte[] aadBuffer,
      int aadSize)
      throws AEADBadTagException;

  /**
   * Initializes state for a non-one-shot encryption operation.
   *
   * @param ptr Context pointer to be used if not zero
   * @param sameKey true iff the key for initialization has been used before
   * @param key Encryption key
   * @param iv Initialization vector
   * @return Native pointer to context data structure, which must be freed using releaseContext() or
   *     encryptDoFinal()
   */
  private static native long encryptInit(long ptr, boolean sameKey, byte[] key, byte[] iv);

  /**
   * Processes some plaintext during a non-one-shot encryption operation. This is essentially a
   * wrapper around OpenSSL's EVP_CipherUpdate.
   *
   * @param ptr Context pointer
   * @param bytes Input data array
   * @param offset Offset within input array to start reading
   * @param length Number of plaintext bytes to process
   * @param output Output array
   * @param outputOffset Offset to start writing within output array
   * @return Actual number of bytes written
   */
  private static native int encryptUpdate(
      long ptr, byte[] bytes, int offset, int length, byte[] output, int outputOffset);

  /**
   * Provides some AAD data to a non-one-shot encryption operation.
   *
   * @param ptr Context pointer
   * @param bytes AAD data array
   * @param offset Start of AAD data within array
   * @param length Amount of AAD data to ingest
   */
  private static native void encryptUpdateAAD(long ptr, byte[] bytes, int offset, int length);

  /**
   * Finishes an encryption operation. This call will implicitly release the native context pointer,
   * even if it fails and throws an exception.
   *
   * @param ptr Native context pointer
   * @param releaseContext if true releases the context
   * @param bytes Final input data (must not be null, even if no data is to be consumed)
   * @param offset Offset within bytes to start reading
   * @param length Length within bytes to read
   * @param output Output buffer
   * @param outputOffset Offset within output buffer to start writing
   * @param tagLen Length of GCM tag
   * @return Number of bytes written in this final operation
   */
  private static native int encryptDoFinal(
      long ptr,
      boolean releaseContext,
      byte[] bytes,
      int offset,
      int length,
      byte[] output,
      int outputOffset,
      int tagLen);

  private static final int BLOCK_SIZE = 128 / 8;

  private final AmazonCorrettoCryptoProvider provider;
  private NativeResource context = null;
  // If an EVP context exists (context != null), then sameKey determines if the EVP context needs to
  // be initialized with both key and iv or if initialization with iv is sufficient:
  // (sameKey == true) implies only iv, and (sameKey == false) implies both key and iv.
  private boolean sameKey = false;
  // A reference to the last Key that was used. This reference is used to optimize initialization
  // when the same Java key object is used to initialize a Cipher that was previously used.
  private Key lastKey = null;
  private byte[] iv, key;
  /** GCM tag length in bytes. */
  private int tagLength = DEFAULT_TAG_LENGTH / 8;

  private int opMode = -1;
  private boolean hasConsumedData = false;
  private boolean needReset = false;
  private boolean contextInitialized = false;

  private final AccessibleByteArrayOutputStream decryptInputBuf =
      new AccessibleByteArrayOutputStream(0, Integer.MAX_VALUE);
  private final AccessibleByteArrayOutputStream decryptAADBuf =
      new AccessibleByteArrayOutputStream(0, Integer.MAX_VALUE);

  AesGcmSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
  }

  private boolean saveNativeContext() {
    switch (provider.getNativeContextReleaseStrategy()) {
      case HYBRID:
        // In HYBRID strategy, the preservation of context depends on if the same key is used or
        // not.
        return sameKey;
      case LAZY:
        return true;
      case EAGER:
        return false;
      default:
        throw new AssertionError("This should not be reachable.");
    }
  }

  @Override
  protected void engineSetMode(final String s) throws NoSuchAlgorithmException {
    if (!"GCM".equalsIgnoreCase(s)) {
      throw new NoSuchAlgorithmException();
    }
  }

  @Override
  protected void engineSetPadding(final String s) throws NoSuchPaddingException {
    if (!"NoPadding".equalsIgnoreCase(s)) {
      throw new NoSuchPaddingException();
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE;
  }

  @Override
  protected int engineGetKeySize(final Key key) throws InvalidKeyException {
    return key.getEncoded().length * 8;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    switch (opMode) {
      case NATIVE_MODE_ENCRYPT:
        return getUpdateOutputSize(inputLen) + tagLength;
      case NATIVE_MODE_DECRYPT:
        return Math.max(0, decryptInputBuf.size() + inputLen - tagLength);
      default:
        throw new IllegalStateException("Cipher not initialized");
    }
  }

  /**
   * Returns the maximum amount of data that could be returned from an update (not doFinal)
   * operation. Not exposed via the Cipher API, but used internally to allocate buffers to return to
   * the caller.
   */
  private int getUpdateOutputSize(final int inputLen) {
    switch (opMode) {
      case NATIVE_MODE_ENCRYPT:
        return inputLen;
      case NATIVE_MODE_DECRYPT:
        // We do not return data from engineUpdate when decrypting - all data is returned from
        // engineDoFinal()
        return 0;
      default:
        throw new IllegalStateException("Cipher not initialized");
    }
  }

  @Override
  protected byte[] engineGetIV() {
    return (iv == null) ? null : iv.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("GCM");
      byte[] ivForParams = iv;
      if (ivForParams == null) {
        // We aren't initialized so we return default and random values
        ivForParams = new byte[DEFAULT_IV_LENGTH_BYTES];
        new LibCryptoRng().nextBytes(ivForParams);
      }
      parameters.init(new GCMParameterSpec(tagLength * 8, ivForParams));
      return parameters;
    } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new Error("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(final int opMode, final Key key, final SecureRandom secureRandom)
      throws InvalidKeyException {
    if (opMode != Cipher.ENCRYPT_MODE && opMode != Cipher.WRAP_MODE) {
      throw new InvalidKeyException("IV required for decrypt");
    }

    final byte[] iv = new byte[12];
    secureRandom.nextBytes(iv);

    try {
      engineInit(opMode, key, new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv), secureRandom);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  protected void engineInit(
      final int jceOpMode,
      final Key key,
      final AlgorithmParameterSpec algorithmParameterSpec,
      final SecureRandom secureRandom)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

    final int opMode = checkOperation(jceOpMode);

    final GCMParameterSpec spec = checkSpecAndTag(algorithmParameterSpec);

    final byte[] newIv = checkIv(spec);

    final byte[] newKey = checkKey(key, lastKey, this.key);

    final boolean sameKey = checkKeyIvPair(opMode, this.key, newKey, this.iv, newIv);

    this.opMode = opMode;
    this.sameKey = sameKey;
    this.iv = newIv;
    this.tagLength = spec.getTLen() / 8;
    this.key = newKey;
    this.lastKey = key;
    this.needReset = false;

    stateReset();
  }

  private static int checkOperation(final int opMode) throws InvalidAlgorithmParameterException {
    switch (opMode) {
      case Cipher.ENCRYPT_MODE:
      case Cipher.WRAP_MODE:
        return NATIVE_MODE_ENCRYPT;
      case Cipher.DECRYPT_MODE:
      case Cipher.UNWRAP_MODE:
        return NATIVE_MODE_DECRYPT;
      default:
        throw new InvalidAlgorithmParameterException("Unsupported cipher mode " + opMode);
    }
  }

  private static GCMParameterSpec checkSpecAndTag(
      final AlgorithmParameterSpec algorithmParameterSpec)
      throws InvalidAlgorithmParameterException {
    if (algorithmParameterSpec instanceof GCMParameterSpec) {
      final GCMParameterSpec spec = (GCMParameterSpec) algorithmParameterSpec;
      if ((spec.getTLen() % 8 != 0) || spec.getTLen() > 128 || spec.getTLen() < 96) {
        throw new InvalidAlgorithmParameterException(
            "Unsupported TLen value; must be one of {128, 120, 112, 104, 96}");
      }
      return spec;
    }
    if (algorithmParameterSpec instanceof IvParameterSpec) {
      return new GCMParameterSpec(
          DEFAULT_TAG_LENGTH, ((IvParameterSpec) algorithmParameterSpec).getIV());
    }
    throw new InvalidAlgorithmParameterException(
        "I don't know how to handle a " + algorithmParameterSpec.getClass());
  }

  private static byte[] checkIv(final GCMParameterSpec spec)
      throws InvalidAlgorithmParameterException {
    final byte[] iv = spec.getIV();
    if (iv == null || iv.length == 0) {
      throw new InvalidAlgorithmParameterException("IV must be at least one byte long");
    }
    return iv;
  }

  private static byte[] checkKey(final Key key, final Key lastKey, final byte[] lastKeyBytes)
      throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("Key can't be null");
    }
    if (key == lastKey) {
      return lastKeyBytes;
    }
    return checkAesKey(key);
  }

  private static boolean checkKeyIvPair(
      final int jceOpMode,
      final byte[] lastKey,
      final byte[] newKey,
      final byte[] lastIv,
      final byte[] newIv)
      throws InvalidAlgorithmParameterException {

    final boolean sameKey = ConstantTime.equals(lastKey, newKey);

    if (sameKey
        && (jceOpMode == Cipher.ENCRYPT_MODE || jceOpMode == Cipher.WRAP_MODE)
        && Arrays.equals(newIv, lastIv)) {
      throw new InvalidAlgorithmParameterException(
          "Cannot reuse same iv and key for GCM encryption");
    }

    return sameKey;
  }

  @Override
  protected void engineInit(
      int opMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    try {
      engineInit(
          opMode, key, algorithmParameters.getParameterSpec(GCMParameterSpec.class), secureRandom);
    } catch (InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] bytes, int offset, int length) {
    byte[] buf = new byte[getUpdateOutputSize(length)];

    int actualLength;
    try {
      actualLength = engineUpdate(bytes, offset, length, buf, 0);
    } catch (ShortBufferException e) {
      throw new AssertionError(e);
    }

    if (actualLength == buf.length) {
      return buf;
    } else {
      return Arrays.copyOf(buf, actualLength);
    }
  }

  @Override
  protected int engineUpdate(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    checkArrayLimits(input, inputOffset, inputLen);

    hasConsumedData = true;

    switch (opMode) {
      case NATIVE_MODE_DECRYPT:
        {
          decryptInputBuf.write(input, inputOffset, inputLen);
          return 0;
        }
      case NATIVE_MODE_ENCRYPT:
        {
          checkOutputBuffer(inputLen, output, outputOffset, false);

          lazyInit();

          // If we have an overlap, we'll need to clone the input buffer before we potentially start
          // overwriting it.
          final byte[] finalBytes;
          final int finalOffset;
          if (Utils.outputClobbersInput(input, inputOffset, inputLen, output, outputOffset)) {
            finalBytes = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
            finalOffset = 0;
          } else {
            finalBytes = input;
            finalOffset = inputOffset;
          }

          return context.use(
              ptr -> encryptUpdate(ptr, finalBytes, finalOffset, inputLen, output, outputOffset));
        }
      default:
        throw new IllegalStateException("Cipher not initialized");
    }
  }

  @Override
  protected void engineUpdateAAD(byte[] bytes, int offset, int length) {
    checkArrayLimits(bytes, offset, length);

    if (hasConsumedData) {
      throw new IllegalStateException("AAD data cannot be updated after calling update()");
    }

    // Older (<= 1.0.1) versions of openssl don't allow AAD data to be provided before the AEAD tag
    if (opMode == NATIVE_MODE_DECRYPT) {
      decryptAADBuf.write(bytes, offset, length);
      return;
    }

    lazyInit();

    internalUpdateAAD(bytes, offset, length);
  }

  private void internalUpdateAAD(byte[] bytes, int offset, int length) {
    while (length > 0) {
      final int stepLength = Math.min(length, 512 * 1024);
      final int finalOffset = offset;

      context.useVoid(ptr -> encryptUpdateAAD(ptr, bytes, finalOffset, stepLength));

      offset += stepLength;
      length -= stepLength;
    }
  }

  @Override
  protected void engineUpdateAAD(ByteBuffer byteBuffer) {
    if (byteBuffer.hasArray()) {
      engineUpdateAAD(
          byteBuffer.array(),
          byteBuffer.arrayOffset() + byteBuffer.position(),
          byteBuffer.remaining());
    } else {
      byte[] tmp = new byte[byteBuffer.remaining()];
      byteBuffer.get(tmp);

      engineUpdateAAD(tmp, 0, tmp.length);
    }

    byteBuffer.position(byteBuffer.limit());
  }

  // We split our final handling of encryption and decryption into two separate methods because they
  // have different requirements and we can optimize them differently. Encryption can be done in an
  // online/streaming manner which allows us to write directly to the output array provided by
  // external callers. Decryption is always done as a single call which requires us to allocate an
  // array to receive the plaintext until we can validate its correctness.
  private int engineEncryptFinal(
      byte[] input, final int inputOffset, int inputLen, final byte[] output, int outputOffset)
      throws ShortBufferException {
    // The following failures should not trigger reset
    if (opMode != NATIVE_MODE_ENCRYPT) {
      throw new IllegalStateException("Cipher not initialized for encryption");
    }
    if (input == null) {
      input = EMPTY_ARRAY;
    }

    checkOutputBuffer(inputLen, output, outputOffset, true);
    checkArrayLimits(input, inputOffset, inputLen);

    // Any future success or failure should trigger reset
    try {
      final boolean clobbers =
          Utils.outputClobbersInput(input, inputOffset, inputLen, output, outputOffset);

      int resultLength = 0;

      if (clobbers) {
        // The input and output potentially overlap. We'll need to make sure we copy the input
        // somewhere safe before proceeding too much further.

        // Since we need to take care of this on engineUpdate as well, we can just delegate to
        // engineUpdate, which will make sure to copy the buffer - on encrypt this is an explicit
        // check, while on decrypt engineUpdate unconditionally copies to a temporary buffer.

        resultLength = engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        outputOffset += resultLength;

        // We processed all of the input in engineUpdate. So there's no longer an overlap to deal
        // with.
        inputLen = 0;
      }

      checkNeedReset();

      this.needReset = true;
      final byte[] finalInput = input;
      final int finalInputLength = inputLen;
      final int finalOutputOffset = outputOffset;

      if (!contextInitialized) {
        // Context has not been initialized, meaning the user called doFinal immediately after
        // init(). In this case
        // we make a single native call to perform the encryption operation in one go.

        if (context != null) {
          return context.use(
              ptr ->
                  oneShotEncrypt(
                      ptr,
                      sameKey,
                      null,
                      finalInput,
                      inputOffset,
                      finalInputLength,
                      output,
                      finalOutputOffset,
                      tagLength,
                      key,
                      iv));
        }
        // We don't have an existing context, however we might want to save one
        if (saveNativeContext()) {
          final long[] ptrOut = new long[1];
          final int outLen =
              oneShotEncrypt(
                  0,
                  false,
                  ptrOut,
                  finalInput,
                  inputOffset,
                  finalInputLength,
                  output,
                  finalOutputOffset,
                  tagLength,
                  key,
                  iv);
          context = new NativeEvpCipherCtx(ptrOut[0]);
          return outLen;
        }
        // We don't need to save the context.
        return oneShotEncrypt(
            0,
            false,
            null,
            finalInput,
            inputOffset,
            finalInputLength,
            output,
            finalOutputOffset,
            tagLength,
            key,
            iv);
      }
      // Context is initialized, which means either updateAAD or update has been invoked after init

      // We need to make sure to add resultLength here; engineUpdate in encrypt mode produces
      // incremental output (unlike in decrypt mode) and so we need to carry forward whatever
      // amount of data it produced in our return value.
      final int finalOutputLen;

      // Should we preserve the context for the next operation?
      if (saveNativeContext()) {
        finalOutputLen =
            context.use(
                ptr ->
                    encryptDoFinal(
                        ptr,
                        false, // releaseContext
                        finalInput,
                        inputOffset,
                        finalInputLength,
                        output,
                        finalOutputOffset,
                        tagLength));
      } else {
        finalOutputLen =
            encryptDoFinal(
                context.take(),
                true, // releaseContext
                input,
                inputOffset,
                finalInputLength,
                output,
                finalOutputOffset,
                tagLength);
        context = null;
      }

      return resultLength + finalOutputLen;
    } finally {
      stateReset();
    }
  }

  private int engineDecryptFinal(
      byte[] input,
      final int inputOffset,
      final int inputLen,
      byte[] output,
      final int outputOffset)
      throws AEADBadTagException, ShortBufferException {
    // The following failures should not trigger reset
    if (opMode != NATIVE_MODE_DECRYPT) {
      throw new IllegalStateException("Cipher not initialized for decryption");
    }
    if (input == null) {
      input = EMPTY_ARRAY;
    }

    checkOutputBuffer(inputLen, output, outputOffset, true);
    checkArrayLimits(input, inputOffset, inputLen);

    // Any future failure (or success) should trigger reset
    try {
      final byte[] workingInputArray;
      final int workingInputOffset;
      final int workingInputLength;
      if (decryptInputBuf.isEmpty()
          && !Utils.outputClobbersInput(input, inputOffset, inputLen, output, outputOffset)) {
        // Nothing has been buffered before and the output buffer does not clobber input. We avoid
        // copying the cipher text into the decryption buffer.
        workingInputArray = input;
        workingInputOffset = inputOffset;
        workingInputLength = inputLen;
      } else {
        // Since it's the final operation, we don't need the buffer to grow beyond what's needed.
        decryptInputBuf.finalWrite(input, inputOffset, inputLen);
        workingInputArray = decryptInputBuf.getDataBuffer();
        workingInputLength = decryptInputBuf.size();
        workingInputOffset = 0;
      }

      if (workingInputLength < tagLength) {
        throw new AEADBadTagException("Input too short - need tag");
      }

      if (context != null) {
        // We already have a context, so let's reuse it.
        return context.use(
            ptr ->
                oneShotDecrypt(
                    ptr,
                    sameKey,
                    null,
                    workingInputArray,
                    workingInputOffset,
                    workingInputLength,
                    output,
                    outputOffset,
                    tagLength,
                    key,
                    iv,
                    // The cost of calling decryptAADBuf.getDataBuffer() when its buffer is empty
                    // is significant for 16-byte decrypt operations (approximately a 7%
                    // performance hit). To avoid this, we reuse the same empty array instead in
                    // this common-case path.
                    decryptAADBuf.isEmpty() ? EMPTY_ARRAY : decryptAADBuf.getDataBuffer(),
                    decryptAADBuf.size()));
      }

      // We don't have an existing context, however we might want to save one
      if (saveNativeContext()) {
        final long[] ptrOut = new long[1];
        final int outlen =
            oneShotDecrypt(
                0,
                false,
                ptrOut,
                workingInputArray,
                workingInputOffset,
                workingInputLength,
                output,
                outputOffset,
                tagLength,
                key,
                iv,

                // The cost of calling decryptAADBuf.getDataBuffer() when its buffer is empty is
                // significant for 16-byte decrypt operations (approximately a 7% performance hit).
                // To avoid this, we reuse the same empty array
                decryptAADBuf.isEmpty() ? EMPTY_ARRAY : decryptAADBuf.getDataBuffer(),
                decryptAADBuf.size());
        context = new NativeEvpCipherCtx(ptrOut[0]);
        return outlen;
      }
      // We don't have a context, and we don't need to save it
      return oneShotDecrypt(
          0,
          false,
          null,
          workingInputArray,
          workingInputOffset,
          workingInputLength,
          output,
          outputOffset,
          tagLength,
          key,
          iv,

          // The cost of calling decryptAADBuf.getDataBuffer() when its buffer is empty is
          // significant for 16-byte decrypt operations (approximately a 7% performance hit).
          // To avoid this, we reuse the same empty array
          decryptAADBuf.isEmpty() ? EMPTY_ARRAY : decryptAADBuf.getDataBuffer(),
          decryptAADBuf.size());
    } catch (final AEADBadTagException e) {
      final int maxFillSize = output.length - outputOffset;
      final int endIndex = outputOffset + Math.min(maxFillSize, engineGetOutputSize(inputLen));
      Arrays.fill(output, outputOffset, endIndex, (byte) 0);
      throw e;
    } finally {
      stateReset();
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] bytes, int offset, int length)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] buf = new byte[engineGetOutputSize(length)];
    int actualLength;
    try {
      switch (opMode) {
        case NATIVE_MODE_ENCRYPT:
          actualLength = engineEncryptFinal(bytes, offset, length, buf, 0);
          break;
        case NATIVE_MODE_DECRYPT:
          actualLength = engineDecryptFinal(bytes, offset, length, buf, 0);
          break;
        default:
          throw new IllegalStateException("Cipher not initialized");
      }
    } catch (ShortBufferException e) {
      throw new AssertionError(e);
    }
    if (actualLength == buf.length) {
      return buf;
    } else {
      // This branch should never happen but is technically allowed by the underlying APIs.
      // So, we cover it just in case.
      return Arrays.copyOf(buf, actualLength);
    }
  }

  @Override
  protected int engineDoFinal(
      byte[] input, final int offset, final int length, final byte[] output, final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    if (opMode == NATIVE_MODE_DECRYPT) {
      return engineDecryptFinal(input, offset, length, output, outputOffset);
    } else if (opMode == NATIVE_MODE_ENCRYPT) {
      return engineEncryptFinal(input, offset, length, output, outputOffset);
    } else {
      throw new IllegalStateException("Cipher not initialized");
    }
  }

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

  /**
   * An array view over a bytebuffer - either directly aliasing the underlying bytebuffer, or a copy
   * of the byte buffer's data. In the latter case, writeback() will copy the data back to the
   * original byte buffer after modifications have been made.
   */
  private static final class ShimArray {
    private final ByteBuffer backingBuffer;
    private final boolean doWriteback;
    public final byte[] array;
    public final int offset, length;

    private ShimArray(final ByteBuffer buffer, final int length) {
      this.backingBuffer = buffer.duplicate();

      boolean hasArray = backingBuffer.hasArray();
      byte[] tmpArray = hasArray ? backingBuffer.array() : null;
      if (tmpArray == null) {
        tmpArray = new byte[length];
        backingBuffer.duplicate().get(tmpArray);
        doWriteback = true;
        offset = 0;
      } else {
        doWriteback = false;
        offset = backingBuffer.arrayOffset() + backingBuffer.position();
      }

      this.array = tmpArray;
      this.length = length;
    }

    private void writeback() {
      if (doWriteback) {
        backingBuffer.duplicate().put(array);
      }
    }
  }

  @Override
  protected int engineUpdate(ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException {
    switch (opMode) {
      case NATIVE_MODE_DECRYPT:
        // Our implementation of engineUpdate for decrypt doesn't actually return any data, we
        // simply buffer the ciphertext and leave the output buffer alone, so we don't bother
        // passing it through. We just write it directly to the buffer.
        decryptInputBuf.write(input);
        return 0;
      case NATIVE_MODE_ENCRYPT:
        ByteBuffer bufferForClear = null;

        // The default JCE implementation of this bytebuffer-to-byte[] shim seems to break when
        // engineGetOutputSize returns more bytes then is actually used in each round (it only calls
        // engineGetOutputSize once, on the entire input size, and does not properly size the output
        // buffer for each round). By coincidence this works as long as the cipher actually knows
        // how much space it's going to use for its bounds checking and the actual buffer sizes for
        // input and output match the cipher block size - but in our case we don't know what EVP's
        // going to do and have to be conservative, requiring a larger output than input buffer. So
        // we have to implement this loop ourselves.

        int initialPosition = output.position();

        if (output.remaining() < engineGetOutputSize(input.remaining())) {
          throw new ShortBufferException();
        }

        if (Utils.outputClobbersInput(input, output)) {
          // We'll just copy the whole input buffer if it might overlap with output.
          ByteBuffer newInput = ByteBuffer.allocate(input.remaining());
          newInput.put(input);
          newInput.flip();
          input = newInput;
          bufferForClear = input;
        }

        while (input.hasRemaining()) {
          int inputChunkSize = Math.min(input.remaining(), 65536);
          ShimArray inputArray = new ShimArray(input, inputChunkSize);
          ShimArray outputArray = new ShimArray(output, engineGetOutputSize(inputChunkSize));

          int outputBytes =
              engineUpdate(
                  inputArray.array,
                  inputArray.offset,
                  inputArray.length,
                  outputArray.array,
                  outputArray.offset);
          outputArray.writeback();

          input.position(input.position() + inputChunkSize);
          output.position(output.position() + outputBytes);
        }
        // If we copied the input, make a best effort attempt to clear the buffer.
        if (bufferForClear != null) {
          Utils.zeroByteBuffer(bufferForClear);
        }

        return output.position() - initialPosition;
      default:
        throw new IllegalStateException("Cipher not initialized");
    }
  }

  private void checkOutputBuffer(
      final int inputLength, final byte[] output, final int outputOffset, final boolean doFinal)
      throws ShortBufferException {
    final int freeBufferSpace = output.length - outputOffset;
    final int requiredBufferSpace =
        doFinal ? engineGetOutputSize(inputLength) : getUpdateOutputSize(inputLength);
    if (inputLength < 0 || outputOffset < 0) {
      throw new ArrayIndexOutOfBoundsException();
    }
    // We only allow outputOffset == output.length if we don't actually need any space for data
    if (outputOffset > output.length
        || (outputOffset == output.length && requiredBufferSpace > 0)) {
      throw new ArrayIndexOutOfBoundsException();
    }

    if (freeBufferSpace < requiredBufferSpace) {
      throw new ShortBufferException(
          String.format(
              "Expected a buffer of at least %d bytes; got %d",
              requiredBufferSpace, freeBufferSpace));
    }
  }

  // @GuardedBy("this") // Restore once replacement for JSR-305 available
  private void lazyInit() {
    if (contextInitialized) {
      return;
    }
    contextInitialized = true;
    if (opMode < 0) {
      throw new IllegalStateException("Cipher not initialized");
    }

    checkNeedReset();

    if (context != null) {
      context.useVoid(ptr -> encryptInit(ptr, sameKey, key, iv));
    } else {
      context = new NativeEvpCipherCtx(encryptInit(0, false, key, iv));
    }
  }

  /**
   * Throws {@link IllegalStateException} if we're about to do a second encrypt call without
   * changing either the key or IV.
   */
  private void checkNeedReset() {
    if (needReset) {
      throw new IllegalStateException("Must change key or IV for GCM mode encryption");
    }
  }

  // @GuardedBy("this") // Restore once replacement for JSR-305 available
  private void stateReset() {
    // While this shouldn't happen, we cover this case to ensure we return to a good state.
    if (context != null && context.isReleased()) {
      context = null;
    }
    decryptInputBuf.reset();
    decryptAADBuf.reset();

    hasConsumedData = false;
    contextInitialized = false;
  }
}
