// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesCtrSpi extends CipherSpi {
  private static final int BLOCK_SIZE_IN_BYTES = 16;
  private static final int IV_SIZE_IN_BYTES = BLOCK_SIZE_IN_BYTES;

  static final int ENC_MODE = 1;
  static final int DEC_MODE = 0;

  private IvParameterSpec ivParamSpec = null; // gets populated on initialization
  private int opMode;
  private int keyLen;
  private SecretKey key = null;
  private boolean needsKeyInit = true;
  private boolean needsNativeInit = true;

  private NativeEvpCipherCtx context = null;
  private final AmazonCorrettoCryptoProvider provider;
  private final boolean saveContext;

  AesCtrSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
    this.saveContext =
        provider.getNativeContextReleaseStrategy() != Utils.NativeContextReleaseStrategy.EAGER;
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (!"CTR".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException();
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    if (!"NoPadding".equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException();
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE_IN_BYTES;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    return inputLen; // No padding, so output len is always equal to inputLen
  }

  @Override
  protected byte[] engineGetIV() {
    if (ivParamSpec == null) {
      return null;
    }
    return ivParamSpec.getIV();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      // CipherSpi docs require that we don't return null here, as the algorithm supports
      // parameters. If we're initialized, return the IV that was specified. Else, generate a new
      // random one but do not update cipher initialization state.
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
      if (ivParamSpec == null) {
        byte[] ivForParams = new byte[BLOCK_SIZE_IN_BYTES];
        new LibCryptoRng().nextBytes(ivForParams);
        parameters.init(new IvParameterSpec(ivForParams));
      } else {
        parameters.init(ivParamSpec);
      }
      return parameters;
    } catch (final InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new RuntimeCryptoException("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.WRAP_MODE) {
      throw new InvalidKeyException("IV required for decrypt");
    }
    try {
      byte[] iv = new byte[IV_SIZE_IN_BYTES];
      random.nextBytes(iv);
      engineInit(opmode, key, new IvParameterSpec(iv), random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException("Failed to initialize with random IV", e);
    }
  }

  @Override
  protected void engineInit(
      final int opmode,
      final Key key,
      final AlgorithmParameterSpec params,
      final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final IvParameterSpec ivParameterSpec = checkAesCtrIv(params);
    init(opmode, key, ivParameterSpec);
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException("Params must not be null");
    }
    try {
      engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
    } catch (final InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  private static IvParameterSpec checkAesCtrIv(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof IvParameterSpec)) {
      if (params == null) {
        throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec cannot be null.");
      } else {
        throw new InvalidAlgorithmParameterException(
            "Unknown AlgorithmParameterSpec: " + params.getClass());
      }
    }
    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    if (ivParameterSpec.getIV().length != IV_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException("Invalid IV for AES/CTR");
    }
    return ivParameterSpec;
  }

  private void init(final int opmode, final Key key, final IvParameterSpec ivParameterSpec)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final byte[] keyBytes = Utils.checkAesKey(key);

    switch (opmode) {
      case Cipher.ENCRYPT_MODE:
      case Cipher.WRAP_MODE:
        this.opMode = ENC_MODE;
        break;
      case Cipher.DECRYPT_MODE:
      case Cipher.UNWRAP_MODE:
        this.opMode = DEC_MODE;
        break;
      default:
        throw new InvalidAlgorithmParameterException("Invalid opmode: " + opmode);
    }
    this.needsKeyInit = this.key != key; // Identity equality check
    this.needsNativeInit = true;
    this.keyLen = keyBytes.length;
    this.key = (SecretKey) key; // Checked by checkAesKey
    this.ivParamSpec = ivParameterSpec;

    // Free any existing context
    if (!saveContext && context != null) {
      context.release();
      context = null;
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    final byte[] output = new byte[inputLen];
    try {
      engineUpdate(input, inputOffset, inputLen, output, 0);
    } catch (ShortBufferException e) {
      throw new AssertionError("Impossible condition", e);
    }
    return output;
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
    Utils.checkArrayLimits(output, outputOffset, inputLen);
    return update(null, input, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineUpdate(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException {
    final int inputLen = input.remaining();
    if (output.remaining() < inputLen) {
      throw new ShortBufferException();
    }

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        update(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            inputLen,
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);
    input.position(input.limit());
    output.position(output.position() + result);
    return result;
  }

  private int update(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {
    final int result;
    if (needsNativeInit) {
      // We need to re-initialize the EVP_CipherCtx object.
      if (context == null) {
        // No context, so create it
        final long[] ctxContainer = new long[] {0};
        result =
            nInitUpdate(
                opMode,
                key.getEncoded(),
                keyLen,
                ivParamSpec.getIV(),
                ctxContainer,
                0,
                inputDirect,
                inputArray,
                inputOffset,
                inputLen,
                outputDirect,
                outputArray,
                outputOffset);
        context = new NativeEvpCipherCtx(ctxContainer[0]);
      } else {
        // The context already exists and we can reuse it.
        // Check to see if the key has changed and so needs to be reinitialized
        final byte[] maybeKeyBytes = needsKeyInit ? key.getEncoded() : null;
        result =
            context.use(
                ctxPtr ->
                    nInitUpdate(
                        opMode,
                        maybeKeyBytes,
                        keyLen,
                        ivParamSpec.getIV(),
                        null,
                        ctxPtr,
                        inputDirect,
                        inputArray,
                        inputOffset,
                        inputLen,
                        outputDirect,
                        outputArray,
                        outputOffset));
      }
    } else {
      // Subsequent update
      result =
          context.use(
              ctxPtr ->
                  nUpdate(
                      opMode,
                      ctxPtr,
                      inputDirect,
                      inputArray,
                      inputOffset,
                      inputLen,
                      outputDirect,
                      outputArray,
                      outputOffset));
    }
    needsKeyInit = false;
    needsNativeInit = false;
    return result;
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] output = new byte[engineGetOutputSize(inputLen)];
    try {
      // NOTE: If we add padding support in the future, the actual output length may
      //       be less than the calculated output length. We should detect that case
      //       and copy the output to an appropriately truncated buffer to return.
      engineDoFinal(input, inputOffset, inputLen, output, 0);
    } catch (ShortBufferException e) {
      throw new AssertionError("Impossible condition", e);
    }
    return output;
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, inputLen);
    return doFinal(null, input, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineDoFinal(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    final int inputLen = input.remaining();
    if (output.remaining() < inputLen) {
      throw new ShortBufferException();
    }

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        doFinal(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            inputLen,
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);
    input.position(input.limit());
    output.position(output.position() + result);
    return result;
  }

  private int doFinal(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {
    final int result;
    if (needsNativeInit) {
      // One-shot operation
      if (context != null) {
        final byte[] maybeKeyBytes = needsKeyInit ? key.getEncoded() : null;
        // Only reason we'd both need need a native init and have context != null is because we're
        // saving the context
        result =
            context.use(
                ctxPtr ->
                    nInitUpdateFinal(
                        opMode,
                        maybeKeyBytes,
                        keyLen,
                        ivParamSpec.getIV(),
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
        needsKeyInit = false;
      } else {
        // context doesn't exist but we might want to save it
        final long[] maybeCtxContainer = saveContext ? new long[1] : null;
        // One-shot operation
        result =
            nInitUpdateFinal(
                opMode,
                key.getEncoded(),
                keyLen,
                ivParamSpec.getIV(),
                maybeCtxContainer,
                0,
                saveContext,
                inputDirect,
                inputArray,
                inputOffset,
                inputLen,
                outputDirect,
                outputArray,
                outputOffset);
        if (saveContext) {
          context = new NativeEvpCipherCtx(maybeCtxContainer[0]);
          needsKeyInit = false;
        }
      }
    } else if (saveContext) {
      result =
          context.use(
              ctxPtr ->
                  nUpdateFinal(
                      opMode,
                      ctxPtr,
                      /*saveCtx*/ true,
                      inputDirect,
                      inputArray,
                      inputOffset,
                      inputLen,
                      outputDirect,
                      outputArray,
                      outputOffset));
    } else {
      // Final operation, take ownership of the context from Janitor
      final long ctxPtr = context.take();
      result =
          nUpdateFinal(
              opMode,
              ctxPtr,
              /*saveCtx*/ false, // then free the context at end of operation
              inputDirect,
              inputArray,
              inputOffset,
              inputLen,
              outputDirect,
              outputArray,
              outputOffset);
      context = null; // nUpdateFinal releases the native context, so just null out our wrapper
      needsKeyInit = true;
    }
    needsNativeInit = true; // Have us reset on the next call

    return result;
  }

  // NOTE: a lot of the below functions could be decomposed into init, update,
  // final, then combined in the java layer, but combining these functions into
  // consolidated JNI lets us only make one JNI call per Java operation.

  private static native int nInitUpdateFinal(
      int opMode,
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

  private static native int nInitUpdate(
      int opMode,
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
      int opMode,
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdateFinal(
      int opMode,
      long ctxPtr,
      boolean saveCtx,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
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
      // BadPaddingException and IllegalBlockSizeException are not reachable for CTR, which has no
      // padding, but the JCA spec only allows throwing InvalidKeyException for engineUnwrap.
      throw new InvalidKeyException("Unwrapping failed", ex);
    }
  }
}
