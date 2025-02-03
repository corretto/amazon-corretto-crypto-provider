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
  // The value of padding is passed to AWS-LC and it respects EVP_CIPHER_CTX_set_padding API:
  // https://github.com/aws/aws-lc/blob/main/include/openssl/cipher.h#L294-L297
  public static final int NO_PADDING = 0;
  public static final int PKCS7_PADDING = 1;
  public static final int ISO10126_PADDING = 2;

  enum Padding {
    NONE(AesCbcSpi.NO_PADDING),
    PKCS7(AesCbcSpi.PKCS7_PADDING),
    ISO10126(AesCbcSpi.ISO10126_PADDING);
    private final int value;

    Padding(final int value) {
      this.value = value;
    }

    int getValue() {
      return value;
    }
  }

  public static final Set<String> AES_CBC_NO_PADDING_NAMES;
  public static final Set<String> AES_CBC_PKCS7_PADDING_NAMES;
  public static final Set<String> AES_CBC_ISO10126_PADDING_NAMES;

  static {
    Loader.load();
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
    // PKCS5Padding with AES/CBC must be treated as PKCS7Padding. PKCS7Padding name is not
    // recognized by SunJCE, but BouncyCastle supports PKCS7Padding as a valid name for the same
    // padding.
    AES_CBC_PKCS7_PADDING_NAMES.add("AES/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_128/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_192/CBC/PKCS5Padding".toLowerCase());
    AES_CBC_PKCS7_PADDING_NAMES.add("AES_256/CBC/PKCS5Padding".toLowerCase());

    AES_CBC_ISO10126_PADDING_NAMES = new HashSet<>();
    AES_CBC_ISO10126_PADDING_NAMES.add("AES/CBC/ISO10126Padding".toLowerCase());
    AES_CBC_ISO10126_PADDING_NAMES.add("AES_128/CBC/ISO10126Padding".toLowerCase());
    AES_CBC_ISO10126_PADDING_NAMES.add("AES_192/CBC/ISO10126Padding".toLowerCase());
    AES_CBC_ISO10126_PADDING_NAMES.add("AES_256/CBC/ISO10126Padding".toLowerCase());
  }

  private static final byte[] EMPTY_ARRAY = new byte[0];
  private static final int BLOCK_SIZE_IN_BYTES = 128 / 8;
  private static final int MODE_NOT_SET = -1;
  // ENC_MODE and DEC_MODE are passed to AWS-LC and respect EVP_CipherInit_ex API:
  // https://github.com/aws/aws-lc/blob/main/include/openssl/cipher.h#L168
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
  // This memory is used during decryption for ISO10126Padding. For ISO10126 padding, we use AES-CBC
  // with no padding and take care of padding/unpadding in ACCP. When decrypting with this padding,
  // this memory is used to keep track of the last block of cipher text. This buffer is only read
  // and written to in the native code. In the Java side, we only set it to zero whenever we
  // initialized.
  private byte[] lastBlock;
  // This flag is initially true. Whenever a non-zero input is passed, it is set to false, and it
  // remains false till the cipher is done processing. This is used during decryption with padding
  // to produce empty output when nothing is passed to the cipher.
  private boolean inputIsEmpty;

  AesCbcSpi(final Padding padding, final boolean saveContext) {
    this.padding = padding.getValue();
    this.cipherState = CipherState.NEEDS_INITIALIZATION;
    this.unprocessedInput = 0;
    this.opMode = MODE_NOT_SET;
    this.key = null;
    this.iv = null;
    this.nativeCtx = null;
    this.saveContext = saveContext;
    this.lastBlock = null;
    this.inputIsEmpty = true;
  }

  private boolean noPadding() {
    return padding == NO_PADDING;
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

    // This method cannot assume if the next operation is going to be engineUpdate or engineDoFinal.
    // We provide separate methods to find the output length for engineUpdates and engineDoFinals to
    // avoid over allocation and alignment checking of input.
    final long all = inputLen + unprocessedInput;

    final long rem = all % BLOCK_SIZE_IN_BYTES;

    // When there is no padding, the output size for enc/dec is at most all.
    if (noPadding()) {
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
    this.inputIsEmpty = true;
    initLastBlock();
  }

  private void initLastBlock() {
    if ((padding != ISO10126_PADDING) || (opMode != DEC_MODE)) {
      return;
    }
    // We only need this buffer decrypting a cipher text that was encrypted with ISO10126Padding.
    if (lastBlock == null) {
      // We allocate 17 bytes. The last byte holds how much of this buffer is used to track the tail
      // of a cipher text during decryption. For example, if there are 4 bytes in this array, its
      // content would look something like the following:
      // [0x00, 0x01, 0x02, 0x03, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0x04]
      lastBlock = new byte[BLOCK_SIZE_IN_BYTES + 1];
    } else {
      Arrays.fill(lastBlock, (byte) 0);
    }
  }

  private static int checkOperation(final int opMode) throws InvalidParameterException {
    return ((opMode == Cipher.ENCRYPT_MODE) || (opMode == Cipher.WRAP_MODE)) ? ENC_MODE : DEC_MODE;
  }

  private static byte[] checkAesCbcIv(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof IvParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "Unknown AlgorithmParameterSpec: " + params.getClass());
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
    // Since we allocate the output's memory, we only check if the cipher is in the correct state.
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeUpdate(inputLen)];
    final int resultLen = update(null, input, inputOffset, inputLen, null, result, 0);
    return result.length == resultLen ? result : Arrays.copyOf(result, resultLen);
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
    if (noPadding() || opMode == ENC_MODE || rem != 0) {
      return (int) (all - rem);
    }
    // When all data (inputLen + unprocessedInput) is block-size aligned, padding is enabled, and we
    // are decrypting, the cipher does not decrypt the last block until doFinal. However, AWS-LC
    // touches the last block of output, as a result, in ACCP, we must over allocate.
    return (int) all;
  }

  private int update(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {

    if (inputLen > 0) {
      inputIsEmpty = false;
    }

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
                          lastBlock,
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
                  lastBlock,
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
                        opMode,
                        padding,
                        ctxPtr,
                        lastBlock,
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
      cleanUpNativeContextIfNeeded(ctxContainer[0]);
      throw e;
    }
  }

  @Override
  protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] inputNotNull = emptyIfNull(input);
    Utils.checkArrayLimits(inputNotNull, inputOffset, inputLen);
    // Since we allocate the output's memory, we only check if the cipher is in the correct state.
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeFinal(inputLen)];
    final int resultLen = doFinal(null, inputNotNull, inputOffset, inputLen, null, result, 0);
    return resultLen == result.length ? result : Arrays.copyOf(result, resultLen);
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    final byte[] inputNotNull = emptyIfNull(input);
    Utils.checkArrayLimits(inputNotNull, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    finalChecks(inputLen, output.length - outputOffset);

    return doFinal(null, inputNotNull, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineDoFinal(final ByteBuffer input, final ByteBuffer output)
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

  // This method is used when calling engineDoFinal to ensure that output is large enough and the
  // input is aligned with block size if needed.
  private int getOutputSizeFinal(final int inputLen) throws IllegalBlockSizeException {
    final long all = ((long) inputLen) + ((long) unprocessedInput);
    final long rem = all % BLOCK_SIZE_IN_BYTES;
    // If there is no padding or if we are decrypting, all the data must be aligned with block size.
    if ((opMode == DEC_MODE || noPadding()) && rem != 0) {
      throw new IllegalBlockSizeException("Input length not multiple of 16 bytes");
    }
    if (noPadding()) {
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

    if (inputLen > 0) {
      inputIsEmpty = false;
    }

    if (inputIsEmpty && (opMode == DEC_MODE) && (!noPadding())) {
      // AWS-LC's behavior in treating empty input when decrypting with padding differs from SunJCE.
      // Here we return zero plaintext.
      return 0;
    }

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
                            lastBlock,
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
                    lastBlock,
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
                          opMode,
                          padding,
                          ctxPtr,
                          true,
                          lastBlock,
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
        final long ctxPtr = nativeCtx == null ? 0 : nativeCtx.take();
        nativeCtx = null;
        if (cipherState == CipherState.INITIALIZED) {
          result =
              nInitUpdateFinal(
                  opMode,
                  padding,
                  key,
                  key.length,
                  iv,
                  null,
                  ctxPtr,
                  false,
                  lastBlock,
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
                  opMode,
                  padding,
                  ctxPtr,
                  false,
                  lastBlock,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  unprocessedInput,
                  outputDirect,
                  outputArray,
                  outputOffset);
        }
      }

      cipherState = CipherState.INITIALIZED;
      unprocessedInput = 0;
      inputIsEmpty = true;
      if (lastBlock != null) {
        Arrays.fill(lastBlock, (byte) 0);
      }

      return result;

    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      cleanUpNativeContextIfNeeded(ctxContainer[0]);
      throw e;
    }
  }

  private void cleanUpNativeContextIfNeeded(final long ctxPtr) {
    if (nativeCtx == null && ctxPtr != 0) {
      Utils.releaseEvpCipherCtx(ctxPtr);
    }
  }

  // We have four JNI calls. Their names start with the letter n, followed by the operations that
  // they perform on the underlying EVP_CIPHER_CTX. For example, nInitUpdate calls init and update
  // on the context.

  // This method is used for one-shot operations, when engineDoFinal is invoked immediately after
  // engineInit.
  private static native int nInitUpdateFinal(
      int opMode,
      int padding,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      boolean saveCtx,
      byte[] lastBlock,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used the first time engineUpdate is used in a multi-step operation.
  private static native int nInitUpdate(
      int opMode,
      int padding,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      byte[] lastBlock,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used the n^th time engineUpdate is used in a multi-step operation, where n >= 2.
  private static native int nUpdate(
      int opMode,
      int padding,
      long ctxPtr,
      byte[] lastBlock,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessedInput,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used  when engineDoFinal is used to finalize a multi-step operation.
  private static native int nUpdateFinal(
      int opMode,
      int padding,
      long ctxPtr,
      boolean saveCtx,
      byte[] lastBlock,
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
