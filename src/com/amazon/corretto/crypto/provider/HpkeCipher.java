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

  private int javaCipherMode_ = 0;
  private EvpHpkeKey key_;
  private HpkeParameterSpec params_;

  private final Object lock_ = new Object();

  HpkeCipher(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
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

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if ((opmode != Cipher.WRAP_MODE) && (opmode != Cipher.UNWRAP_MODE)) {
      throw new IllegalStateException("HpkeCipher only supports WRAP_MODE and UNWRAP_MODE");
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
    if ((opmode == Cipher.WRAP_MODE) && !(key instanceof EvpHpkePublicKey)) {
      throw new IllegalStateException("Need PublicKey to wrap");
    }
    if ((opmode == Cipher.UNWRAP_MODE) && !(key instanceof EvpHpkePrivateKey)) {
      throw new IllegalStateException("Need PrivateKey to unwrap");
    }
    synchronized (lock_) {
      params_ = (HpkeParameterSpec) params;
      javaCipherMode_ = opmode;
      key_ = opmode == Cipher.WRAP_MODE ? (EvpHpkePublicKey) key : (EvpHpkePrivateKey) key;
    }
  }

  /**
   * Performs HPKE single-shot encryption, as specified in Section 6.1 of RFC 9180.
   *
   * @return concatenation of KEM encapsulated key and encrypted ciphertext
   */
  @Override
  protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (javaCipherMode_ != Cipher.WRAP_MODE) {
      throw new IllegalStateException("Cipher must be in WRAP_MODE");
    }
    if ((key_ == null) || !(key_ instanceof EvpHpkePublicKey)) {
      throw new IllegalStateException("PublicKey should be set before wrapping.");
    }
    try {
      final byte[] encoded = Utils.encodeForWrapping(provider_, key);
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (final BadPaddingException e) {
      throw new InvalidKeyException("Failed to wrap key", e);
    }
  }

  /**
   * Performs HPKE single-shot decryption, as specified in Section 6.1 of RFC 9180.
   *
   * @return decrypted plaintext
   */
  @Override
  protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (javaCipherMode_ != Cipher.UNWRAP_MODE) {
      throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
    }
    if ((key_ == null) || !(key_ instanceof EvpHpkePrivateKey)) {
      throw new IllegalStateException("PrivateKey should be set before unwrapping.");
    }
    try {
      final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
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

    if (input == output) {
      // TODO: is it okay if they are non-overlapping, support that case if necessary.
      throw new IllegalStateException("input and output must be separate arrays");
    }

    synchronized (lock_) {
      if (key_ == null) {
        throw new IllegalStateException("key should be set before finalizing");
      }
      if ((javaCipherMode_ != Cipher.WRAP_MODE) && (javaCipherMode_ != Cipher.UNWRAP_MODE)) {
        throw new IllegalStateException("HpkeCipher only supports WRAP_MODE and UNWRAP_MODE");
      }
      if ((javaCipherMode_ == Cipher.WRAP_MODE) && !(key_ instanceof EvpHpkePublicKey)) {
        throw new IllegalStateException("PublicKey should be set before wrapping.");
      }
      if ((javaCipherMode_ == Cipher.UNWRAP_MODE) && !(key_ instanceof EvpHpkePrivateKey)) {
        throw new IllegalStateException("PrivateKey should be set before wrapping.");
      }

      final int result;
      result =
          key_.use(
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
                      output,
                      outputOffset));
      return result;
    }
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    if (params_ == null) {
      throw new IllegalStateException("params should be set before getOutputSize");
    }
    if ((javaCipherMode_ != Cipher.WRAP_MODE) && (javaCipherMode_ != Cipher.UNWRAP_MODE)) {
      throw new IllegalStateException("cipher mode should be set before getOutputSize");
    }
    return hpkeOutputSize(
        javaCipherMode_, params_.getKemId(), params_.getKdfId(), params_.getAeadId(), inputLen);
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
    byte[] output = new byte[engineGetOutputSize(inputLen)];
    try {
      int len = engineDoFinal(input, inputOffset, inputLen, output, 0);
      if (len != output.length) {
        throw new RuntimeCryptoException(
            "HpkeCipher expected output of length " + output.length + ", got output of len " + len);
      }
      return output;
    } catch (ShortBufferException e) {
      throw new RuntimeException(e);
    }
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
  protected void engineUpdateAAD(byte[] src, int offset, int len) {
    // TODO: implement AAD support
    throw new IllegalStateException("HpkeCipher currently does not support AAD");
  }

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
    throw new IllegalStateException("HpkeCipher does not support updates");
  }

  @Override
  protected int engineUpdate(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    throw new IllegalStateException("HpkeCipher does not support updates");
  }
}
