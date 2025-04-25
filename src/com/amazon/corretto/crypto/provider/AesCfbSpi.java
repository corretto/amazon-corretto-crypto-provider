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

  private final byte[] iv;
  private int opMode;
  private int keyLen;
  private byte[] key;
  private long ctxPtr;
  private boolean initialized;

  AesCfbSpi() {
    iv = new byte[IV_SIZE_IN_BYTES];
    initialized = false;
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    if (!"CFB".equalsIgnoreCase(mode) && !"CFB128".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
    }
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    if (!"NoPadding".equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException("Unsupported padding: " + padding);
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE_IN_BYTES;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    return inputLen;
  }

  @Override
  protected byte[] engineGetIV() {
    return iv.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    try {
      byte[] newIv = new byte[IV_SIZE_IN_BYTES];
      random.nextBytes(newIv);
      engineInit(opmode, key, new IvParameterSpec(newIv), random);
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
      throw new InvalidAlgorithmParameterException("params must be an instance of IvParameterSpec");
    }
    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    final byte[] ivBytes = ivParameterSpec.getIV();
    if (ivBytes.length != IV_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "Provided IV must be of length " + IV_SIZE_IN_BYTES);
    }

    if (!"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("Key's format must be raw");
    }
    final byte[] keyBytes = key.getEncoded();
    if (keyBytes == null) {
      throw new InvalidKeyException("Key must be transparent");
    }
    if (keyBytes.length != KEY_LEN_AES128 && keyBytes.length != KEY_LEN_AES256) {
      throw new InvalidKeyException("Key length must be " + KEY_LEN_AES128 + " or " + KEY_LEN_AES256);
    }

    init(opmode, keyBytes, ivBytes);
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException(
        "IV must be provided by passing an instance of IvParameterSpec.");
  }

  private void init(final int opmode, final byte[] keyBytes, final byte[] ivBytes) {
    this.opMode = (opmode == Cipher.ENCRYPT_MODE) ? ENC_MODE : DEC_MODE;
    this.keyLen = keyBytes.length;
    this.key = keyBytes.clone();
    System.arraycopy(ivBytes, 0, iv, 0, IV_SIZE_IN_BYTES);
    this.initialized = true;
    
    // Free any existing context
    if (ctxPtr != 0) {
      nUpdateFinal(opMode, ctxPtr, false, null, null, 0, 0, null, null, 0);
      ctxPtr = 0;
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
    
    if (!initialized) {
      throw new IllegalStateException("Cipher not initialized");
    }
    
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, inputLen);
    
    if (ctxPtr == 0) {
      // First update, need to initialize
      final long[] ctxContainer = new long[1];
      final int result = nInitUpdate(
          opMode,
          key,
          keyLen,
          iv,
          ctxContainer,
          0,
          null,
          input,
          inputOffset,
          inputLen,
          null,
          output,
          outputOffset);
      ctxPtr = ctxContainer[0];
      return result;
    } else {
      // Subsequent update
      return nUpdate(
          opMode,
          ctxPtr,
          null,
          input,
          inputOffset,
          inputLen,
          null,
          output,
          outputOffset);
    }
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
    if (!initialized) {
      throw new IllegalStateException("Cipher not initialized");
    }
    
    if (inputLen > 0) {
      Utils.checkArrayLimits(input, inputOffset, inputLen);
    }
    
    if (inputLen > 0) {
      Utils.checkArrayLimits(output, outputOffset, inputLen);
    }
    
    int result;
    if (ctxPtr == 0) {
      // One-shot operation
      result = nInitUpdateFinal(
          opMode,
          key,
          keyLen,
          iv,
          null,
          0,
          false,
          null,
          input,
          inputOffset,
          inputLen,
          null,
          output,
          outputOffset);
    } else {
      // Final operation with existing context
      result = nUpdateFinal(
          opMode,
          ctxPtr,
          false,
          null,
          input,
          inputOffset,
          inputLen,
          null,
          output,
          outputOffset);
      ctxPtr = 0;
    }
    
    return result;
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      if (ctxPtr != 0) {
        nUpdateFinal(opMode, ctxPtr, false, null, null, 0, 0, null, null, 0);
        ctxPtr = 0;
      }
    } finally {
      super.finalize();
    }
  }

  private static native int nInitUpdateFinal(
      int opMode,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      boolean saveCtx,
      Object inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      Object outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nInitUpdate(
      int opMode,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      Object inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      Object outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdate(
      int opMode,
      long ctxPtr,
      Object inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      Object outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdateFinal(
      int opMode,
      long ctxPtr,
      boolean saveCtx,
      Object inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      Object outputDirect,
      byte[] outputArray,
      int outputOffset);
}