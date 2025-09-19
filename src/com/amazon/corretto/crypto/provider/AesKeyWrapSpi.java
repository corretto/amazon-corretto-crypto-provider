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
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

final class AesKeyWrapSpi extends CipherSpi {
  private static final int BLOCK_SIZE = 128 / 8;

  static {
    Loader.load();
  }

  private final AmazonCorrettoCryptoProvider provider;
  private SecretKey jceKey;
  private byte[] keyBytes;
  private int opmode = -1; // must be set by init(..)
  private final AccessibleByteArrayOutputStream buffer;
  private byte[] iv;

  AesKeyWrapSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
    this.buffer = new AccessibleByteArrayOutputStream();
    this.iv = null;
  }

  private static native int wrapKey(
      byte[] key, byte[] iv, byte[] input, int inLen, byte[] output, int outOf);

  private static native int unwrapKey(
      byte[] key, byte[] iv, byte[] input, int inLen, byte[] output, int outOf);

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (mode != null && !"KW".equals(mode)) {
      throw new NoSuchAlgorithmException(mode + " cannot be used");
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    if (padding != null && !"NoPadding".equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException("Unsupported padding " + padding);
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE;
  }

  @Override
  protected int engineGetKeySize(final Key key) throws InvalidKeyException {
    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("Can't encode key to obtain length");
    }
    int keyLen = key.getEncoded().length;
    Arrays.fill(encoded, (byte) 0);
    return Math.multiplyExact(keyLen, 8);
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    final int totalInLen = Math.addExact(buffer.size(), inputLen);
    switch (opmode) {
      case Cipher.WRAP_MODE:
      case Cipher.ENCRYPT_MODE:
        return getWrappedLen(totalInLen);
      case Cipher.UNWRAP_MODE:
      case Cipher.DECRYPT_MODE:
      default:
        return estimateUnwrappedLen(totalInLen);
    }
  }

  // RFC-3394 on success writes in_len + 8 bytes to out and returns in_len + 8
  private static int getWrappedLen(final int unwrappedLen) {
    return Math.addExact(unwrappedLen, 8);
  }

  private static int estimateUnwrappedLen(final int wrappedLen) {
    if (wrappedLen < 16) {
      return 8;
    }
    return Math.subtractExact(wrappedLen, 8);
  }

  @Override
  protected byte[] engineGetIV() {
    return this.iv == null ? null : this.iv.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    if (this.iv == null) {
      return null;
    }

    try {
      final AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
      parameters.init(new IvParameterSpec(this.iv));
      return parameters;
    } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new Error("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom ignored) throws InvalidKeyException {
    implInit(opmode, key, null);
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom ignored2)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    IvParameterSpec ivParameterSpec = null;
    if (params != null) {
      try {
        ivParameterSpec = params.getParameterSpec(IvParameterSpec.class);
      } catch (InvalidParameterSpecException e) {
        throw new InvalidAlgorithmParameterException(e);
      }
    }
    engineInit(opmode, key, ivParameterSpec, ignored2);
  }

  @Override
  protected void engineInit(
      int opmode, Key key, AlgorithmParameterSpec params, SecureRandom ignored2)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final byte[] iv = (params != null) ? getIv(params) : null;
    validateIv(iv);
    implInit(opmode, key, iv);
  }

  private void implInit(int opmode, Key key, byte[] iv) throws InvalidKeyException {
    if (opmode != Cipher.UNWRAP_MODE
        && opmode != Cipher.WRAP_MODE
        && opmode != Cipher.ENCRYPT_MODE
        && opmode != Cipher.DECRYPT_MODE) {
      throw new UnsupportedOperationException("Unsupported mode");
    }
    if (key == null) {
      throw new InvalidKeyException("Null key");
    }
    if (key != jceKey) {
      if (!(key instanceof SecretKey)) {
        throw new InvalidKeyException("Need a SecretKey");
      }
      if (!"RAW".equalsIgnoreCase(key.getFormat())) {
        throw new InvalidKeyException("Need a raw format key");
      }
      if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
        throw new InvalidKeyException("Expected an AES key");
      }
      if (this.keyBytes != null) {
        Arrays.fill(this.keyBytes, (byte) 0);
        this.keyBytes = null;
      }
      this.keyBytes = key.getEncoded();
      if (keyBytes == null) {
        throw new InvalidKeyException("Key doesn't support encoding");
      }
      this.jceKey = (SecretKey) key;
    }
    this.opmode = opmode;
    this.iv = iv;
    this.buffer.reset();
  }

  private void validateIv(byte[] iv) throws InvalidAlgorithmParameterException {
    if (iv != null && iv.length < 8) {
      throw new InvalidAlgorithmParameterException("IV length is less than 8 bytes");
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] in, int inOffset, int inLen) {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for update");
    }
    implUpdate(in, inOffset, inLen);
    // we don't output individual blocks, we instead output the whole result at doFinal
    return null;
  }

  @Override
  protected int engineUpdate(byte[] in, int inOffset, int inLen, byte[] out, int outOf)
      throws ShortBufferException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for update");
    }
    // NOTE: we ignore |out| and |outOf| entirely because this CipherSpi implementation
    //       does not output "blocks" incrementally, we merely buffer the input data and
    //       and incorporate it into the final one-shot crypt call over JNI. see CipherSpi
    //       javadoc for engineUpdate for more details.
    implUpdate(in, inOffset, inLen);
    // we don't output individual blocks, we instead output the whole result at doFinal
    return 0;
  }

  private void implUpdate(byte[] in, int inOffset, int inLen) {
    if (in != null && in.length > 0 && Math.addExact(inOffset, inLen) <= in.length) {
      this.buffer.write(in, inOffset, inLen);
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] in, int inOffset, int inLen) throws BadPaddingException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for finalization");
    }
    return implDoFinal(in, inOffset, inLen);
  }

  @Override
  protected int engineDoFinal(byte[] in, int inOffset, int inLen, byte[] out, int outOffset)
      throws ShortBufferException, BadPaddingException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for finalization");
    }
    int estimatedOutLen = engineGetOutputSize(inLen);
    if (out.length - outOffset < estimatedOutLen) {
      throw new ShortBufferException("Output buffer needs size of at least " + estimatedOutLen);
    }
    return implDoFinal(in, inOffset, inLen, out, outOffset);
  }

  private byte[] implDoFinal(byte[] in, int inOffset, int inLen) throws BadPaddingException {
    final int estimatedOutLen = engineGetOutputSize(inLen);
    byte[] out = new byte[estimatedOutLen];
    final int actualOutLen = implDoFinal(in, inOffset, inLen, out, 0);
    // If we overestimated the size of the output (possible in unwrapping),
    // we need to copy only the output's bytes over to a newer, smaller
    // byte array. Java's inability to truncate arrays after creation
    // forces us to do this. Note that in the common case of block-aligned
    // key sizes, our estimates are correct and this extra copy is avoided.
    if (actualOutLen < estimatedOutLen) {
      final byte[] tmp = new byte[actualOutLen];
      System.arraycopy(out, 0, tmp, 0, tmp.length);
      Arrays.fill(out, (byte) 0);
      out = tmp;
    }
    return out;
  }

  private int implDoFinal(byte[] in, int inOffset, int inLen, byte[] out, int outOffset)
      throws BadPaddingException {
    implUpdate(in, inOffset, inLen);

    final int outLen;
    try {
      if ((buffer.size() % 8) != 0) {
        throw new BadPaddingException("Wrap data must be a multiple of 8 bytes");
      }

      switch (opmode) {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
          outLen = wrapKey(keyBytes, iv, buffer.getDataBuffer(), buffer.size(), out, outOffset);
          break;
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
          outLen = unwrapKey(keyBytes, iv, buffer.getDataBuffer(), buffer.size(), out, outOffset);
          break;
        default:
          throw new IllegalStateException("Cipher not initialized for finalization");
      }
    } finally {
      buffer.reset();
    }
    return outLen;
  }

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (opmode != Cipher.WRAP_MODE) {
      throw new IllegalStateException("Cipher must be init'd in WRAP_MODE");
    }

    byte[] encoded = null;
    try {
      encoded = Utils.encodeForWrapping(provider, key);
      return implDoFinal(encoded, 0, encoded.length);
    } catch (BadPaddingException | RuntimeCryptoException e) {
      throw new InvalidKeyException("Wrapping failed", e);
    } finally {
      if (encoded != null) {
        Arrays.fill(encoded, (byte) 0);
      }
    }
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (opmode != Cipher.UNWRAP_MODE) {
      throw new IllegalStateException("Cipher must be init'd in UNWRAP_MODE");
    }

    byte[] unwrappedKey = null;
    try {
      unwrappedKey = implDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(provider, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (BadPaddingException | InvalidKeySpecException | RuntimeCryptoException e) {
      throw new InvalidKeyException("Unwrapping failed", e);
    } finally {
      if (unwrappedKey != null) {
        Arrays.fill(unwrappedKey, (byte) 0);
      }
    }
  }

  private static byte[] getIv(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof IvParameterSpec)) {
      final String paramClass =
          Optional.ofNullable(params).map(Object::getClass).map(Object::toString).orElse("null");
      throw new InvalidAlgorithmParameterException("Unknown AlgorithmParameterSpec: " + paramClass);
    }

    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    return ivParameterSpec.getIV();
  }
}
