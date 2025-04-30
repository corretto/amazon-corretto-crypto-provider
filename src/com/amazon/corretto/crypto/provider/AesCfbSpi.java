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
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesCfbSpi extends CipherSpi {
  private static final int BLOCK_SIZE_IN_BYTES = 16;
  private static final int IV_SIZE_IN_BYTES = BLOCK_SIZE_IN_BYTES;
  private static final int KEY_LEN_AES128 = 16;
  private static final int KEY_LEN_AES256 = 32;

  static final int ENC_MODE = 1;
  static final int DEC_MODE = 0;

  private IvParameterSpec ivParamSpec = null; // gets populated on initialization
  private int opMode;
  private int keyLen;
  private byte[] key = null;
  private NativeResource context = null;
  private final AmazonCorrettoCryptoProvider provider;

  AesCfbSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (!"CFB".equalsIgnoreCase(mode)) {
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
      // random one but
      // do not update cipher initialization state.
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
    try {
      byte[] iv = new byte[IV_SIZE_IN_BYTES];
      random.nextBytes(iv);
      ivParamSpec = new IvParameterSpec(iv);
      engineInit(opmode, key, ivParamSpec, random);
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
    if (!(params instanceof IvParameterSpec)) {
      throw new InvalidAlgorithmParameterException("Params must be an instance of IvParameterSpec");
    }
    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    final byte[] ivBytes = ivParameterSpec.getIV();
    init(opmode, key, ivBytes);
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

  private void init(final int opmode, final Key key, final byte[] ivBytes)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (ivBytes.length != IV_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "Provided IV must be of length " + IV_SIZE_IN_BYTES);
    }

    if (!"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("Key's format must be RAW");
    }
    final byte[] keyBytes = key.getEncoded();
    if (keyBytes == null) {
      throw new InvalidKeyException("Key must support encoding");
    }
    if (keyBytes.length != KEY_LEN_AES128 && keyBytes.length != KEY_LEN_AES256) {
      throw new InvalidKeyException(
          "Key length must be " + KEY_LEN_AES128 + " or " + KEY_LEN_AES256);
    }

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
    this.key = keyBytes.clone();
    this.ivParamSpec = new IvParameterSpec(ivBytes); // TODO [childw] enforce IV constraints

    // Free any existing context
    if (context != null) {
      context.release();
      context = null;
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    if (inputLen == 0) {
      return new byte[0];
    }

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
    if (inputLen == 0) {
      return 0;
    }

    if (ivParamSpec == null) {
      throw new IllegalStateException("Cipher not initialized");
    }

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
      final int actualLen = engineDoFinal(input, inputOffset, inputLen, output, 0);
      if (actualLen == output.length) {
        return output;
      } else {
        return Arrays.copyOf(output, actualLen);
      }
    } catch (ShortBufferException e) {
      throw new AssertionError("Impossible condition", e);
    }
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    if (ivParamSpec == null) {
      throw new IllegalStateException("Cipher not initialized");
    }

    if (inputLen > 0) {
      Utils.checkArrayLimits(input, inputOffset, inputLen);
    }

    if (inputLen > 0) {
      Utils.checkArrayLimits(output, outputOffset, inputLen);
    }

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
