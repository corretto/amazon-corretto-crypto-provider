// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.checkAesKey;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesCbcSpi extends CipherSpi {
  public static final Set<String> AES_CBC_NO_PADDING_NAMES;
  public static final Set<String> AES_CBC_PKCS7_PADDING_NAMES;

  static {
    AES_CBC_NO_PADDING_NAMES = new HashSet<>();
    AES_CBC_NO_PADDING_NAMES.add("AES/CBC/NoPadding".toLowerCase());
    AES_CBC_NO_PADDING_NAMES.add("AES_128/CBC/NoPadding".toLowerCase());
    AES_CBC_NO_PADDING_NAMES.add("AES_192/CBC/NoPadding".toLowerCase());
    AES_CBC_NO_PADDING_NAMES.add("AES_256/CBC/NoPadding".toLowerCase());

    AES_CBC_PKCS7_PADDING_NAMES = new HashSet<>();
    AES_CBC_PKCS7_PADDING_NAMES.add("AES/CBC/PKCS7Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_128/CBC/PKCS7Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_192/CBC/PKCS7Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_256/CBC/PKCS7Padding".toLowerCase());
    // PKCS5Padding with AES/CBC should be treated as PKCS7Padding
    AES_CBC_PKCS7_PADDING_NAMES.add("AES/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_128/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_192/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_256/CBC/PKCS5Padding".toLowerCase());
  }

  private static final byte[] EMPTY_ARRAY = new byte[0];
  private static final int NO_PADDING = 0;
  private static final int PKCS7_PADDING = 1;
  private static final int BLOCK_SIZE_IN_BYTES = 128 / 8;
  private static final int MODE_NOT_SET = -1;
  private static final int ENC_MODE = 1;
  private static final int DEC_MODE = 0;

  private enum CipherState {
    NEEDS_INITIALIZATION,
    INITIALIZED,
    UPDATED,
  }

  // State
  private CipherState cipherState;
  private final int padding;
  // CBC processes data one block at a time. There are two scenarios where not all the input passed
  // to engineUpdate is processed:
  //     1. Input length is not a multiple of the block size,
  //     2. Padding is enabled and cipher is configured for decryption.
  // This variable keeps track of the unprocessed bytes.
  private int unprocessedInput;
  private int opMode;
  private byte[] key;
  private byte[] iv;
  // nativeCtx is used to avoid memory leaks in case of multi-step operations or when the
  // EVP_CIPHER_CTX needs to be preserved.
  private NativeEvpCipherCtx nativeCtx;
  // Determines if the EVP_CIPHER_CTX used should be released after doFinal or not. This is
  // controlled by a system property.
  private final boolean saveContext;

  AesCbcSpi(final boolean paddingEnabled, final boolean saveContext) {
    this.padding = paddingEnabled ? PKCS7_PADDING : NO_PADDING;
    this.cipherState = CipherState.NEEDS_INITIALIZATION;
    this.unprocessedInput = 0;
    this.opMode = MODE_NOT_SET;
    this.key = null;
    this.iv = null;
    this.nativeCtx = null;
    this.saveContext = saveContext;
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    // no op. One only needs to provide an implementation if the same Spi class instance can be used
    // for different modes.
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    // no op. One only needs to provide an implementation if the same Spi class instance is used for
    // different paddings.
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE_IN_BYTES;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    // There is no need to check if the Cipher is initialized since
    // javax.crypto.Cipher::getOutputSize checks that.
    final long all = inputLen + unprocessedInput;

    final long rem = all % BLOCK_SIZE_IN_BYTES;

    // When there is no padding, the output size for enc/dec is at most all.
    if (padding == NO_PADDING) {
      return (int) (all);
    }

    // If padding is enabled and encrypting, the largest output size is during doFinal
    if (opMode == ENC_MODE) {
      return (int) ((all + BLOCK_SIZE_IN_BYTES) - rem);
    }

    // If padding is enabled and decrypting, the largest output size is during doFinal
    return (int) all;
  }

  @Override
  protected byte[] engineGetIV() {
    return iv == null ? null : iv.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
      byte[] ivForParams = iv;
      if (ivForParams == null) {
        // We aren't initialized, so we return default and random values
        ivForParams = new byte[BLOCK_SIZE_IN_BYTES];
        new LibCryptoRng().nextBytes(ivForParams);
      }
      parameters.init(new IvParameterSpec(ivForParams));
      return parameters;
    } catch (final InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new Error("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.WRAP_MODE) {
      throw new InvalidKeyException("IV required for decrypt");
    }

    final byte[] iv = new byte[BLOCK_SIZE_IN_BYTES];
    random.nextBytes(iv);

    try {
      engineInit(opmode, key, new IvParameterSpec(iv), null);
    } catch (final InvalidAlgorithmParameterException e) {
      throw new RuntimeCryptoException(e);
    }
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, final AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    try {
      engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), null);
    } catch (final InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  @Override
  protected void engineInit(
      final int opmode,
      final Key key,
      final AlgorithmParameterSpec params,
      final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final int opMode = checkOperation(opmode);
    final byte[] iv = checkAesCbcIv(params);
    final byte[] keyBytes = checkAesKey(key);

    // All checks passes, so we update the state:
    this.cipherState = CipherState.INITIALIZED;
    this.opMode = opMode;
    this.iv = iv;
    this.key = keyBytes;
    this.unprocessedInput = 0;
  }

  private static int checkOperation(final int opMode) throws InvalidParameterException {
    return ((opMode == Cipher.ENCRYPT_MODE) || (opMode == Cipher.WRAP_MODE)) ? ENC_MODE : DEC_MODE;
  }

  private static byte[] checkAesCbcIv(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof IvParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "I don't know how to handle a " + params.getClass());
    }

    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    final byte[] iv = ivParameterSpec.getIV();
    if (iv.length != BLOCK_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException("Invalid IV for AES/CBC");
    }

    return iv;
  }

  @Override
  protected byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeUpdate(inputLen)];
    update(null, input, inputOffset, inputLen, null, result, 0);
    // For update, getOutputSizeUpdate returns the exact required size, therefore there is no need
    // for trimming the result;
    return result;
  }

  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    updateChecks(inputLen, output.length - outputOffset);
    return update(null, input, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineUpdate(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException {
    updateChecks(input.remaining(), output.remaining());

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        update(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            input.remaining(),
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);

    input.position(input.limit());
    output.position(output.position() + result);

    return result;
  }

  private void finalOrUpdateStateCheck() {
    if (cipherState == CipherState.NEEDS_INITIALIZATION) {
      throw new IllegalStateException("Cipher needs initialization.");
    }
  }

  private void updateChecks(final int inputLen, final int outputLen) throws ShortBufferException {
    finalOrUpdateStateCheck();
    if (outputLen < getOutputSizeUpdate(inputLen)) {
      throw new ShortBufferException();
    }
  }

  private int getOutputSizeUpdate(final int inputLen) {
    final long all = ((long) inputLen) + ((long) unprocessedInput);
    if (all == 0) {
      return 0;
    }
    final long rem = all % BLOCK_SIZE_IN_BYTES;
    if (padding == NO_PADDING || opMode == ENC_MODE || rem != 0) {
      return (int) (all - rem);
    }
    // When all data (inputLen + unprocessedInput) is block-size aligned, padding is enabled, and we
    // are decrypting, the cipher does not decrypt the last block until doFinal.
    return (int) (all - BLOCK_SIZE_IN_BYTES);
  }

  private int update(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {

    // Unlike, doFinal (which needs to decide if a context should be released or not), update always
    // has to save the context.

    final long[] ctxContainer = new long[] {0};
    try {
      final int result;
      if (cipherState == CipherState.INITIALIZED) {
        if (nativeCtx != null) {
          result =
              nativeCtx.use(
                  ctxPtr ->
                      nInitUpdate(
                          opMode,
                          padding,
                          key,
                          key.length,
                          iv,
                          null,
                          ctxPtr,
                          inputDirect,
                          inputArray,
                          inputOffset,
                          inputLen,
                          outputDirect,
                          outputArray,
                          outputOffset));
        } else {
          result =
              nInitUpdate(
                  opMode,
                  padding,
                  key,
                  key.length,
                  iv,
                  ctxContainer,
                  0,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  outputDirect,
                  outputArray,
                  outputOffset);
          nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
        }
        cipherState = CipherState.UPDATED;
      } else {
        // Cipher is in UPDATED state: this is not the first time update is being invoked.
        result =
            nativeCtx.use(
                ctxPtr ->
                    nUpdate(
                        ctxPtr,
                        inputDirect,
                        inputArray,
                        inputOffset,
                        inputLen,
                        unprocessedInput,
                        outputDirect,
                        outputArray,
                        outputOffset));
        // No need to update the cipherState since it's already in UPDATED state.
      }
      final long all = inputLen + unprocessedInput;
      unprocessedInput = (int) (all - result);
      return result;
    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      saveNativeContextIfNeeded(ctxContainer[0]);
      throw e;
    }
  }

  private static native int nInitUpdate(
      int opMode,
      int padding,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdate(
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessedInput,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    Utils.checkArrayLimits(emptyIfNull(input), inputOffset, inputLen);
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeFinal(inputLen)];
    final int resultLen = doFinal(null, emptyIfNull(input), inputOffset, inputLen, null, result, 0);
    return resultLen == result.length ? result : Arrays.copyOf(result, resultLen);
  }

  @Override
  protected int engineDoFinal(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Utils.checkArrayLimits(emptyIfNull(input), inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    finalChecks(inputLen, output.length - outputOffset);

    return doFinal(null, emptyIfNull(input), inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    finalChecks(input.remaining(), output.remaining());

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        doFinal(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            input.remaining(),
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);

    input.position(input.limit());
    output.position(output.position() + result);

    return result;
  }

  private void finalChecks(final int inputLen, final int outputLen)
      throws IllegalBlockSizeException, ShortBufferException {
    finalOrUpdateStateCheck();
    if (outputLen < getOutputSizeFinal(inputLen)) {
      throw new ShortBufferException(outputLen + "<" + getOutputSizeFinal(inputLen));
    }
  }

  private int getOutputSizeFinal(final int inputLen) throws IllegalBlockSizeException {
    final long all = ((long) inputLen) + ((long) unprocessedInput);
    final long rem = all % BLOCK_SIZE_IN_BYTES;
    // If there is no padding or if we are decrypting, all the data must be aligned with block size.
    if ((opMode == DEC_MODE || padding == NO_PADDING) && rem != 0) {
      throw new IllegalBlockSizeException();
    }
    if (padding == NO_PADDING) {
      return (int) all;
    }
    // When encrypting with padding enabled ...
    if (opMode == ENC_MODE) {
      return (int) ((all + BLOCK_SIZE_IN_BYTES) - rem);
    }
    // When decrypting with padding enabled, we don't know exactly how many bytes the input has
    // without decrypting first.
    return (int) all;
  }

  private int doFinal(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {

    // There are four possibilities:
    // 1. Save context AND Cipher is in INITIALIZED state => nInitUpdateFinal(saveContext == true)
    // 2. Save context AND Cipher is in UPDATED state => nUpdateFinal(saveContext == true)
    // 3. Don't save context AND Cipher is in INITIALIZED state => nInitUpdateFinal(saveContext ==
    // false)
    // 4. Don't save context AND Cipher is in UPDATED state => nUpdateFinal(saveContext == false)

    final long[] ctxContainer = new long[] {0};
    try {
      final int result;
      if (saveContext) {
        if (cipherState == CipherState.INITIALIZED) {
          if (nativeCtx != null) {
            result =
                nativeCtx.use(
                    ctxPtr ->
                        nInitUpdateFinal(
                            opMode,
                            padding,
                            key,
                            key.length,
                            iv,
                            null,
                            ctxPtr,
                            true,
                            inputDirect,
                            inputArray,
                            inputOffset,
                            inputLen,
                            outputDirect,
                            outputArray,
                            outputOffset));
          } else {
            result =
                nInitUpdateFinal(
                    opMode,
                    padding,
                    key,
                    key.length,
                    iv,
                    ctxContainer,
                    0,
                    true,
                    inputDirect,
                    inputArray,
                    inputOffset,
                    inputLen,
                    outputDirect,
                    outputArray,
                    outputOffset);
            nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
          }
        } else {
          // Cipher is in UPDATE state, which means update was called at least once, and it needs to
          // save the context. No need to call registerMess since the first update has already done
          // this.
          result =
              nativeCtx.use(
                  ctxPtr ->
                      nUpdateFinal(
                          null,
                          ctxPtr,
                          true,
                          inputDirect,
                          inputArray,
                          inputOffset,
                          inputLen,
                          unprocessedInput,
                          outputDirect,
                          outputArray,
                          outputOffset));
        }
      } else {
        // Don't need to save the context
        if (cipherState == CipherState.INITIALIZED) {
          result =
              nInitUpdateFinal(
                  opMode,
                  padding,
                  key,
                  key.length,
                  iv,
                  null,
                  nativeCtx == null ? 0 : nativeCtx.take(),
                  false,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  outputDirect,
                  outputArray,
                  outputOffset);
        } else {
          // Cipher is in UPDATE state and don't need to save the context
          result =
              nUpdateFinal(
                  null,
                  nativeCtx.take(),
                  false,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  unprocessedInput,
                  outputDirect,
                  outputArray,
                  outputOffset);
        }
        nativeCtx = null;
      }

      cipherState = CipherState.INITIALIZED;
      unprocessedInput = 0;

      return result;

    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      if (saveContext) {
        saveNativeContextIfNeeded(ctxContainer[0]);
      } else {
        nativeCtx = null;
      }
      throw e;
    }
  }

  private void saveNativeContextIfNeeded(final long ctxPtr) {
    if (nativeCtx == null && ctxPtr != 0) {
      nativeCtx = new NativeEvpCipherCtx(ctxPtr);
    }
  }

  private static native int nInitUpdateFinal(
      int opMode,
      int padding,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      boolean saveCtx,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdateFinal(
      long[] ctxContainer,
      long ctxPtr,
      boolean saveCtx,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessedInput,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    try {
      final byte[] encoded = Utils.encodeForWrapping(key);
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (final BadPaddingException ex) {
      // This is not reachable when encrypting.
      throw new InvalidKeyException("Wrapping failed", ex);
    }
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    try {
      final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
      // BadPaddingException and IllegalBlockSizeException can happen for AES/CBC/PKCS7Padding, but
      // the JCA spec only allows throwing InvalidKeyException for engineUnwrap.
      throw new InvalidKeyException("Unwrapping failed", ex);
    }
  }

  private static byte[] emptyIfNull(final byte[] array) {
    return array == null ? EMPTY_ARRAY : array;
  }
}
