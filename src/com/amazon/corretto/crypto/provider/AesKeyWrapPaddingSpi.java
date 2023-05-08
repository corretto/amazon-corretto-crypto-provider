// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

final class AesKeyWrapPaddingSpi extends CipherSpi {
  private static final int BLOCK_SIZE = 128 / 8;

  static {
    Loader.load();
  }

  private final AmazonCorrettoCryptoProvider provider;
  private SecretKey jceKey;
  private byte[] keyBytes;
  private int opmode = -1; // must be set by init(..)
  private final AccessibleByteArrayOutputStream buffer;

  AesKeyWrapPaddingSpi(final AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
    buffer = new AccessibleByteArrayOutputStream();
  }

  private static native int wrapKey(byte[] key, byte[] input, int inLen, byte[] output, int outOf);

  private static native int unwrapKey(
      byte[] key, byte[] input, int inLen, byte[] output, int outOf);

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (mode != null && !"KWP".equals(mode)) {
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

  // RFC-5649 describes KWP's padding scheme. The key is padded out to a byte
  // length divisible by 8, then an additional 8-byte block of padding is
  // appended.
  private static int getWrappedLen(final int unwrappedLen) {
    final int paddingLen;
    if (unwrappedLen % 8 == 0) {
      paddingLen = 0;
    } else {
      paddingLen = 8 - (unwrappedLen % 8);
    }
    return Math.addExact(Math.addExact(unwrappedLen, paddingLen), 8);
  }

  // Because the key is padded before it is wrapped (i.e. encrypted), we have
  // no way of knowing the unwrapped key's precise size beforehand. The best
  // we can do is to "guess" by accounting for the 8 bytes of padding that
  // are added in all cases before wrapping.
  private static int estimateUnwrappedLen(final int wrappedLen) {
    if (wrappedLen < 16) {
      return 8;
    }
    return Math.subtractExact(wrappedLen, 8);
  }

  @Override
  protected byte[] engineGetIV() {
    return null;
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom ignored) throws InvalidKeyException {
    implInit(opmode, key);
  }

  @Override
  protected void engineInit(
      int opmode, Key key, AlgorithmParameters ignored1, SecureRandom ignored2)
      throws InvalidKeyException {
    implInit(opmode, key);
  }

  @Override
  protected void engineInit(
      int opmode, Key key, AlgorithmParameterSpec ignored1, SecureRandom ignored2)
      throws InvalidKeyException {
    implInit(opmode, key);
  }

  private void implInit(int opmode, Key key) throws InvalidKeyException {
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
      if (keyBytes != null) {
        Arrays.fill(keyBytes, (byte) 0);
        keyBytes = null;
      }
      keyBytes = key.getEncoded();
      if (keyBytes == null) {
        throw new InvalidKeyException("Key doesn't support encoding");
      }
      jceKey = (SecretKey) key;
    }
    this.opmode = opmode;
    buffer.reset();
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
      buffer.write(in, inOffset, inLen);
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] in, int inOffset, int inLen) {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for finalization");
    }
    return implDoFinal(in, inOffset, inLen);
  }

  @Override
  protected int engineDoFinal(byte[] in, int inOffset, int inLen, byte[] out, int outOffset)
      throws ShortBufferException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher not initialized for finalization");
    }
    int estimatedOutLen = engineGetOutputSize(inLen);
    if (out.length - outOffset < estimatedOutLen) {
      throw new ShortBufferException("Output buffer needs size of at least " + estimatedOutLen);
    }
    return implDoFinal(in, inOffset, inLen, out, outOffset);
  }

  private byte[] implDoFinal(byte[] in, int inOffset, int inLen) {
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

  private int implDoFinal(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
    implUpdate(in, inOffset, inLen);
    final int outLen;
    try {
      switch (opmode) {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
          outLen = wrapKey(keyBytes, buffer.getDataBuffer(), buffer.size(), out, outOffset);
          break;
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
          outLen = unwrapKey(keyBytes, buffer.getDataBuffer(), buffer.size(), out, outOffset);
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
    } catch (RuntimeCryptoException e) {
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
    } catch (InvalidKeySpecException | RuntimeCryptoException e) {
      throw new InvalidKeyException("Unwrapping failed", e);
    } finally {
      if (unwrappedKey != null) {
        Arrays.fill(unwrappedKey, (byte) 0);
      }
    }
  }
}
