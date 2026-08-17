// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
  private byte[] key = null;
  private NativeEvpCipherCtx context = null;
  private final AmazonCorrettoCryptoProvider provider;
  // TODO: saveContext is computed but not yet consumed. Wiring it into engineDoFinal's saveCtx
  // arguments naively is unsafe: the one-shot path passes a null ctxContainer (would throw
  // natively), and even once plumbed, the simple `context == null` state check can't distinguish
  // "no context" from "unkeyed leftover context from a prior op," so a reused context could skip
  // EVP_CipherInit_ex and silently continue with a stale key/IV/counter. Needs a design decision
  // (extra state bit vs. narrowing scope to release-timing only) before enabling.
  // We also need to consider explicitly not passing in key bytes when the key is unchanged to avoid
  // the cost of the AES key-schedule.
  private final boolean saveContext;

  AesCtrSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
    this.saveContext =
        provider.getNativeContextReleaseStrategy() == Utils.NativeContextReleaseStrategy.LAZY;
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
        this.opMode = ENC_MODE;
        break;
      case Cipher.DECRYPT_MODE:
        this.opMode = DEC_MODE;
        break;
      default:
        throw new InvalidAlgorithmParameterException("Invalid opmode: " + opmode);
    }
    this.keyLen = keyBytes.length;
    this.key = keyBytes;
    this.ivParamSpec = ivParameterSpec;

    // Free any existing context
    if (context != null) {
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

    if (context == null) {
      // First update, need to initialize
      final long[] ctxContainer = new long[] {0};
      final int result =
          nInitUpdate(
              opMode,
              key,
              keyLen,
              ivParamSpec.getIV(),
              ctxContainer,
              0,
              input,
              inputOffset,
              inputLen,
              output,
              outputOffset);
      context = new NativeEvpCipherCtx(ctxContainer[0]);
      return result;
    }
    // Subsequent update
    return context.use(
        ctxPtr -> nUpdate(opMode, ctxPtr, input, inputOffset, inputLen, output, outputOffset));
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

    int result;
    if (context == null) {
      // One-shot operation
      result =
          nInitUpdateFinal(
              opMode,
              key,
              keyLen,
              ivParamSpec.getIV(),
              null,
              0,
              false,
              input,
              inputOffset,
              inputLen,
              output,
              outputOffset);
    } else {
      // Final operation, take ownership of the context from Janitor
      final long ctxPtr = context.take();
      result =
          nUpdateFinal(
              opMode,
              ctxPtr,
              /*saveCtx*/ false, // then free the context at end of operation
              input,
              inputOffset,
              inputLen,
              output,
              outputOffset);
      context = null; // nUpdateFinal releases the native context, so just null out our wrapper
    }

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
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      byte[] outputArray,
      int outputOffset);

  private static native int nInitUpdate(
      int opMode,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdate(
      int opMode,
      long ctxPtr,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdateFinal(
      int opMode,
      long ctxPtr,
      boolean saveCtx,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      byte[] outputArray,
      int outputOffset);
}
