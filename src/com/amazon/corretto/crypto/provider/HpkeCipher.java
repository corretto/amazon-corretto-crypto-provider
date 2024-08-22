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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class HpkeCipher extends CipherSpi {

  static {
    Loader.load();
  }

  private final AmazonCorrettoCryptoProvider provider_;
  private final Object lock_ = new Object();

  private int javaCipherMode_ = -1;
  private EvpHpkeKey key_;
  private HpkeParameterSpec params_;

  /** tracks whether the cipher has been used (to encrypt, decrypt, wrap, or unwrap) */
  private boolean finalized_ = false;

  private final AccessibleByteArrayOutputStream aadBuffer_;

  HpkeCipher(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider_ = provider;
    aadBuffer_ = new AccessibleByteArrayOutputStream();
  }

  // Core Native Methods
  // -------------------

  /**
   * Performs single-shot HPKE encryption or decryption, as specified in Section 6.1 of RFC 9180.
   *
   * @return number of bytes written to output, and -1 if failed.
   */
  private static native int hpkeCipher(
      long keyHandle,
      int javaCipherMode,
      int kemId,
      int KdfId,
      int aeadId,
      byte[] input,
      int inputOffset,
      int inputLen,
      byte[] aad,
      int aadLen,
      byte[] output,
      int outputOffset);

  /**
   * Computes the number of bytes the output buffer needs to be for wrapping and unwrapping.
   *
   * <p>For wrapping, the size is greater than the input buffer since the output buffer also needs
   * to include an AEAD tag and KEM encapsulate.
   *
   * <p>For unwrapping, the size is smaller, since the output does not need the AEAD tag or the KEM
   * encapsulate.
   */
  private static native int hpkeOutputSize(
      int javaCipherMode, int kemId, int KdfId, int aeadId, int inputLen);

  // Core Java Methods
  // -----------------

  private static void checkModeKeyParams(int opmode, Key key, AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException, InvalidKeyException {
    if ((opmode != Cipher.WRAP_MODE)
        && (opmode != Cipher.UNWRAP_MODE)
        && (opmode != Cipher.ENCRYPT_MODE)
        && (opmode != Cipher.DECRYPT_MODE)) {
      throw new IllegalStateException(
          "HpkeCipher only supports WRAP_MODE, UNWRAP_MODE, ENCRYPT_MODE, and DECRYPT_MODE.");
    }
    if (key == null) {
      throw new IllegalStateException("HpkeCipher does not support a null key.");
    }
    if (params == null) {
      throw new InvalidAlgorithmParameterException(
          "HpkeCipher does not support a null parameters.");
    }
    if (!(params instanceof HpkeParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "HpkeCipher only supports HpkeParameterSpec parameters.");
    }
    if (!(key instanceof EvpHpkeKey)) {
      throw new InvalidKeyException("HpkeCipher only supports EvpHpkeKey keys.");
    }
    if (((EvpHpkeKey) key).getSpec() != params) {
      throw new InvalidKeyException("Spec of key does not match the params provided");
    }
    if (key instanceof EvpHpkePublicKey) {
      if ((opmode != Cipher.WRAP_MODE) && (opmode != Cipher.ENCRYPT_MODE)) {
        throw new IllegalStateException("Need PublicKey to wrap and encrypt");
      }
    } else if (key instanceof EvpHpkePrivateKey) {
      if ((opmode != Cipher.UNWRAP_MODE) && (opmode != Cipher.DECRYPT_MODE)) {
        throw new IllegalStateException("Need PrivateKey to unwrap and decrypt");
      }
    } else {
      throw new InvalidKeyException(
          "HpkeCipher only supports EvpHpkePublicKey and EvpHpkePrivate key types, given: "
              + key.getClass());
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    checkModeKeyParams(opmode, key, params);
    synchronized (lock_) {
      javaCipherMode_ = opmode;
      if ((opmode == Cipher.UNWRAP_MODE) || (opmode == Cipher.DECRYPT_MODE)) {
        key_ = (EvpHpkePrivateKey) key;
      } else {
        key_ = (EvpHpkePublicKey) key;
      }
      params_ = (HpkeParameterSpec) params;
      finalized_ = false;
      aadBuffer_.reset();
    }
  }

  /**
   * Internal method to perform single-shot HPKE encryption or decryption, specified in Section 6.1
   * of RFC 9180.
   *
   * @return number of bytes written to output
   */
  private int internalOneShotHpke(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    finalized_ = true; // cannot update AAD after this function is called
    if (input == output) {
      // TODO: is it okay if they are non-overlapping, support that case if necessary.
      throw new IllegalStateException("input and output must be separate arrays");
    }
    if ((outputOffset > output.length)
        || (inputOffset > input.length)
        || ((inputOffset + inputLen) > input.length)) {
      throw new ArrayIndexOutOfBoundsException();
    }
    if (engineGetOutputSize(inputLen) > (output.length - outputOffset)) {
      throw new ShortBufferException();
    }
    synchronized (lock_) {
      try {
        checkModeKeyParams(javaCipherMode_, key_, params_);
      } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
        throw new IllegalStateException(e);
      }

      byte[] aad = aadBuffer_.getDataBuffer();
      int aadLen = aadBuffer_.size();

      return key_.use(
          ptr ->
              hpkeCipher(
                  ptr,
                  javaCipherMode_,
                  params_.getKemId(),
                  params_.getKdfId(),
                  params_.getAeadId(),
                  input,
                  inputOffset,
                  inputLen,
                  aad,
                  aadLen,
                  output,
                  outputOffset));
    }
  }
  /**
   * Internal method to perform single-shot HPKE encryption or decryption, specified in Section 6.1
   * of RFC 9180.
   *
   * @return a new buffer with the output
   */
  byte[] internalOneShotHpke(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    byte[] output = new byte[engineGetOutputSize(inputLen)];
    try {
      int len = internalOneShotHpke(input, inputOffset, inputLen, output, 0);
      if (len != output.length) {
        throw new RuntimeCryptoException(
            "HpkeCipher expected output of length " + output.length + ", got output of len " + len);
      }
      return output;
    } catch (ShortBufferException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Supply AAD to HPKE. Must be called before the cipher is used, i.e., before DoFinal, Wrap, or
   * Unwrap.
   */
  @Override
  protected void engineUpdateAAD(byte[] src, int offset, int len) {
    synchronized (lock_) {
      if (finalized_) {
        throw new IllegalStateException(
            "Cannot update AAD after HpkeCipher has been used to Wrap, Unwrap, Encrypt, or"
                + " Decrypt");
      }
      aadBuffer_.write(src, offset, len);
    }
  }

  /**
   * Wraps key using HPKE single-shot encryption.
   *
   * @return concatenation of KEM encapsulated key and encrypted ciphertext
   */
  @Override
  protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (javaCipherMode_ != Cipher.WRAP_MODE) {
      throw new IllegalStateException("Cipher must be in WRAP_MODE");
    }
    try {
      final byte[] encoded = Utils.encodeForWrapping(provider_, key);
      return internalOneShotHpke(encoded, 0, encoded.length);
    } catch (final BadPaddingException e) {
      throw new InvalidKeyException("Failed to wrap key", e);
    }
  }

  /**
   * Unwraps key using HPKE single-shot decryption.
   *
   * @return decrypted key
   */
  @Override
  protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (javaCipherMode_ != Cipher.UNWRAP_MODE) {
      throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
    }
    try {
      final byte[] unwrappedKey = internalOneShotHpke(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(provider_, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException e) {
      throw new InvalidKeyException("Failed to unwrap key", e);
    }
  }

  /**
   * Performs HPKE single-shot encryption or decryption, as specified in Section 6.1 of RFC 9180.
   *
   * @return number of bytes written to output
   */
  @Override
  protected int engineDoFinal(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    if ((javaCipherMode_ != Cipher.ENCRYPT_MODE) && (javaCipherMode_ != Cipher.DECRYPT_MODE)) {
      throw new IllegalStateException("cipher must be in ENCRYPT_MODE or DECRYPT_MODE");
    }
    return internalOneShotHpke(input, inputOffset, inputLen, output, outputOffset);
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    synchronized (lock_) {
      try {
        checkModeKeyParams(javaCipherMode_, key_, params_);
        return hpkeOutputSize(
            javaCipherMode_, params_.getKemId(), params_.getKdfId(), params_.getAeadId(), inputLen);
      } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  // Boilerplate Methods
  // -------------------

  @Override
  protected AlgorithmParameters engineGetParameters() {
    AlgorithmParameters params;
    try {
      params = AlgorithmParameters.getInstance("HPKE");
      params.init(params_);
      return params;
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    return internalOneShotHpke(input, inputOffset, inputLen);
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException("cannot initialize HpkeCipher with null params");
    }
    try {
      AlgorithmParameterSpec spec = params.getParameterSpec(HpkeParameterSpec.class);
      engineInit(opmode, key, spec, random);
    } catch (InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
    if (key instanceof EvpHpkeKey) {
      try {
        engineInit(opmode, key, ((EvpHpkeKey) key).getSpec(), random);
      } catch (InvalidAlgorithmParameterException e) {
        throw new InvalidKeyException(e);
      }
    } else {
      throw new InvalidKeyException("HpkeCipher can only be initialized with EvpHpkeKey.");
    }
  }

  // Unsupported Methods
  // -------------------

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    throw new NoSuchAlgorithmException("HpkeCipher does not support modes");
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("HpkeCipher does not support padding");
  }

  @Override
  protected int engineGetBlockSize() {
    throw new IllegalStateException("HpkeCipher does not support block sizes");
  }

  @Override
  protected byte[] engineGetIV() {
    throw new IllegalStateException("HpkeCipher does not support IVs");
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    throw new IllegalStateException("HpkeCipher currently does not support updates");
  }

  @Override
  protected int engineUpdate(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    throw new IllegalStateException("HpkeCipher currently does not support updates");
  }
}
