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
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesXtsSpi extends CipherSpi {
  private static final int BLOCK_SIZE_IN_BYTES = 128 / 8;
  private static final int TWEAK_SIZE_IN_BYTES = BLOCK_SIZE_IN_BYTES;
  private static final int KEY_SIZE_IN_BYTES = (256 * 2) / 8;
  private static final int MINIMUM_INPUT_SIZE_FOR_AES_XTS = BLOCK_SIZE_IN_BYTES;

  // bytes 0 to TWEAK_SIZE_IN_BYTES - 1 is the tweak value, and bytes TWEAK_SIZE_IN_BYTES
  // represent the key
  private final byte[] packedTweakKey;

  private CipherState cipherState;

  AesXtsSpi() {
    packedTweakKey = new byte[TWEAK_SIZE_IN_BYTES + KEY_SIZE_IN_BYTES];
    cipherState = CipherState.CREATED;
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    if (!"XTS".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException();
    }
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
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
    return getExactOutputSize(inputLen);
  }

  private int getExactOutputSize(final int inputLen) {
    if (inputLen < MINIMUM_INPUT_SIZE_FOR_AES_XTS) {
      throw new IllegalArgumentException(
          "AES-XTS requires input of at least " + MINIMUM_INPUT_SIZE_FOR_AES_XTS + " bytes.");
    }
    return inputLen;
  }

  @Override
  protected byte[] engineGetIV() {
    return cipherState == CipherState.CREATED
        ? null
        : Arrays.copyOfRange(packedTweakKey, 0, TWEAK_SIZE_IN_BYTES);
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    throw new UnsupportedOperationException(
        "Tweak must be provided by passing an instance of IvParameterSpec.");
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
    final byte[] tweak = ivParameterSpec.getIV();
    if (tweak.length != TWEAK_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "Provided tweak must be of length " + TWEAK_SIZE_IN_BYTES);
    }

    if (!(key instanceof SecretKey)) {
      throw new InvalidKeyException("Key must of type SecretKey");
    }
    final SecretKey secretKey = (SecretKey) key;
    if (!"RAW".equalsIgnoreCase(secretKey.getFormat())) {
      throw new InvalidKeyException("Key's format must be raw");
    }
    // Since AES-XTS is not a standard name, we do not put any restriction on
    // secretKey.getAlgorithm()
    final byte[] keyBytes = secretKey.getEncoded();
    if (keyBytes == null) {
      throw new InvalidKeyException("Key must be transparent");
    }
    if (keyBytes.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("Key length must be " + KEY_SIZE_IN_BYTES);
    }

    init(opmode, keyBytes, tweak);
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException(
        "Tweak must be provided by passing an instance of IvParameterSpec.");
  }

  private void init(final int opmode, final byte[] key, final byte[] tweak)
      throws InvalidAlgorithmParameterException {
    if (cipherState.shouldCheckForReuse(opmode) && checkKeyTweakEquality(key, tweak)) {
      throw new InvalidAlgorithmParameterException(
          "The combination of key and tweak cannot be reused.");
    }
    cipherState = CipherState.fromOp(opmode);
    System.arraycopy(tweak, 0, packedTweakKey, 0, TWEAK_SIZE_IN_BYTES);
    System.arraycopy(key, 0, packedTweakKey, TWEAK_SIZE_IN_BYTES, KEY_SIZE_IN_BYTES);
  }

  private boolean checkKeyTweakEquality(final byte[] key, final byte[] tweak) {
    for (int i = 0; i != TWEAK_SIZE_IN_BYTES; i++) {
      if (packedTweakKey[i] != tweak[i]) return false;
    }

    return ConstantTime.equals(packedTweakKey, TWEAK_SIZE_IN_BYTES, KEY_SIZE_IN_BYTES, key);
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    throw new UnsupportedOperationException(
        "Multiple-part encryption or decryption is not supported. Consider using DoFinal.");
  }

  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset) {
    throw new UnsupportedOperationException(
        "Multiple-part encryption or decryption is not supported. Consider using DoFinal.");
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] output = new byte[getExactOutputSize(inputLen)];
    try {
      engineDoFinal(input, inputOffset, inputLen, output, 0);
    } catch (final ShortBufferException e) {
      throw new AssertionError(e);
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
    cipherState.checkCipherStateForFinal();
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    final int outputLen = output.length - outputOffset;
    Utils.checkArrayLimits(output, outputOffset, outputLen);
    final int actualOutputLen = getExactOutputSize(inputLen);
    if (outputLen < actualOutputLen) {
      throw new ShortBufferException("Output buffer is not large enough.");
    }

    if (Utils.outputClobbersInput(input, inputOffset, inputLen, output, outputOffset)) {
      final byte[] tempOutput = engineDoFinal(input, inputOffset, inputLen);
      System.arraycopy(tempOutput, 0, output, outputOffset, tempOutput.length);
    } else {
      if (cipherState == CipherState.ENCRYPT_INIT) {
        encrypt(input, inputOffset, inputLen, output, outputOffset);
      } else {
        decrypt(input, inputOffset, inputLen, output, outputOffset);
      }
    }

    cipherState = cipherState.nextStateAfterDoFinal();
    return actualOutputLen;
  }

  private void encrypt(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
    if (input != output) {
      enc(packedTweakKey, input, inputOffset, inputLen, output, outputOffset);
    } else {
      encSameBuffer(packedTweakKey, input, inputOffset, inputLen, outputOffset);
    }
  }

  private void decrypt(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
    if (input != output) {
      dec(packedTweakKey, input, inputOffset, inputLen, output, outputOffset);
    } else {
      decSameBuffer(packedTweakKey, input, inputOffset, inputLen, outputOffset);
    }
  }

  private static native void enc(
      byte[] packedTweakKey,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset);

  private static native void encSameBuffer(
      byte[] packedTweakKey, byte[] input, int inputOffset, int inputLen, int outputOffset);

  private static native void dec(
      byte[] packedTweakKey,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset);

  private static native void decSameBuffer(
      byte[] packedTweakKey, byte[] input, int inputOffset, int inputLen, int outputOffset);

  private enum CipherState {
    CREATED, // Cipher has just been created.
    ENCRYPT_INIT, // Cipher is initialized for encryption
    ENCRYPT_DONE, // doFinal has been invoked for a cipher initialized for encryption
    DECRYPT_INIT, // Cipher is initialized for decryption
    DECRYPT_DONE; // doFinal has been invoked for a cipher initialized for decryption

    public boolean shouldCheckForReuse(final int opmode) {
      // The combination of a key and a tweak should not be used to encrypt
      // different data units. Here we provided a limited guard for such a
      // bad pattern.
      return this == ENCRYPT_DONE && opmode == Cipher.ENCRYPT_MODE;
    }

    public void checkCipherStateForFinal() {
      if (this != ENCRYPT_INIT && this != DECRYPT_INIT) {
        throw new IllegalStateException("Cipher is not initialized.");
      }
    }

    public CipherState nextStateAfterDoFinal() {
      return this == ENCRYPT_INIT ? ENCRYPT_DONE : DECRYPT_DONE;
    }

    static CipherState fromOp(final int opmode) {
      if (opmode == Cipher.ENCRYPT_MODE) {
        return ENCRYPT_INIT;
      }
      if (opmode == Cipher.DECRYPT_MODE) {
        return DECRYPT_INIT;
      }
      throw new UnsupportedOperationException("Only Encrypt and Decrypt are supported.");
    }
  }
}
