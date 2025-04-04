// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.EMPTY_ARRAY;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

class RsaCipher extends CipherSpi {
  private static final int HANDLE_USAGE_IGNORE = 1;
  private static final int HANDLE_USAGE_USE = 2;
  private static final int HANDLE_USAGE_CREATE = 3;

  // From openssl/rsa.h
  private enum Padding {
    /** PKCS #1 v1.5 */
    PKCS1(1, "PKCS1Padding"),
    NO_PADDING(3, "NoPadding"),
    /** PKCS #1 v2.0 */
    OAEP(4, "OAEP");

    private final int nativeVal;
    private final String paddingStr;

    private Padding(final int val, final String paddingIn) {
      nativeVal = val;
      paddingStr = paddingIn;
    }
  }

  static {
    Loader.load();
  }

  private static native int cipher(
      long keyPtr,
      int mode,
      int padding,
      long oaepMdPtr,
      long mgfMdPtr,
      byte[] input,
      int inOff,
      int inLength,
      byte[] output,
      int outOff)
      throws BadPaddingException;

  private final AmazonCorrettoCryptoProvider provider_;
  private final Object lock_ = new Object();
  private final Padding padding_;
  private final boolean allowParamUpdates_;

  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private int mode_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private RSAKey key_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private int keySizeBytes_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private int paddingSize_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private OAEPParameterSpec oaepParams_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private EvpKey nativeKey_;
  // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
  private AccessibleByteArrayOutputStream buffer_;

  RsaCipher(
      AmazonCorrettoCryptoProvider provider,
      final Padding padding,
      final int paddingSize,
      final boolean allowParamUpdates) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    padding_ = padding;
    paddingSize_ = paddingSize;
    allowParamUpdates_ = allowParamUpdates;
    oaepParams_ = padding == Padding.OAEP ? OAEPParameterSpec.DEFAULT : null;
  }

  @Override
  protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    synchronized (lock_) {
      assertInitialized();
      final byte[] result = new byte[engineGetOutputSize(inputLen)];

      try {
        final int len = engineDoFinal(input, inputOffset, inputLen, result, 0);

        if (len == result.length) {
          return result;
        } else {
          return Arrays.copyOf(result, len);
        }
      } catch (final ShortBufferException ex) {
        throw new AssertionError(ex);
      }
    }
  }

  @Override
  protected int engineDoFinal(
      byte[] input, int inputOffset, int inputLen, final byte[] output, final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    synchronized (lock_) {
      assertInitialized();

      if (buffer_.size() != 0) { // Not one-shot
        if (input != null) {
          buffer_.write(input, inputOffset, inputLen);
        }
        input = buffer_.getDataBuffer();
        inputOffset = 0;
        inputLen = buffer_.size();
      }
      // One-shot, no input. Cipher only calls engineDoFinal with null input in doFinal overloads
      // that don't take an input buffer, and in those cases, inputOffset and inputLen are 0.
      // We set them here anyways to be safe, because the API makes no such guarantee.
      else if (input == null) {
        input = Utils.EMPTY_ARRAY;
        inputOffset = 0;
        inputLen = 0;
      }

      if (output.length - outputOffset < engineGetOutputSize(inputLen)) {
        throw new ShortBufferException();
      }
      if (mode_ == Cipher.ENCRYPT_MODE || mode_ == Cipher.WRAP_MODE) {
        if (inputLen > keySizeBytes_ - paddingSize_) {
          throw new IllegalBlockSizeException(
              "Data must not be longer than " + (keySizeBytes_ - paddingSize_) + " bytes");
        }
        // We're allowed to pad NO_PADDING with zero bytes on the left.
        // This is because RSA fundamentally works on positive integers so
        // adding new high-order zero bytes does not change the numeric value
        // of the input and thus does not change the output.
        if (padding_.equals(Padding.NO_PADDING) && inputLen < keySizeBytes_) {
          byte[] tmp = new byte[keySizeBytes_];
          System.arraycopy(input, inputOffset, tmp, keySizeBytes_ - inputLen, inputLen);
          input = tmp;
          inputOffset = 0;
          inputLen = keySizeBytes_;
        }
      } else {
        if (inputLen > keySizeBytes_) {
          throw new IllegalBlockSizeException(
              "Data must not be longer than " + keySizeBytes_ + " bytes");
        }
      }

      final long oaepMdPtr;
      final long mgfMdPtr;
      if (padding_ == Padding.OAEP) {
        oaepMdPtr = Utils.getMdPtr(oaepParams_.getDigestAlgorithm());
        mgfMdPtr =
            Utils.getMdPtr(
                ((MGF1ParameterSpec) oaepParams_.getMGFParameters()).getDigestAlgorithm());
      } else {
        oaepMdPtr = 0;
        mgfMdPtr = 0;
      }

      final byte[] finalInput = input;
      final int finalInputOffset = inputOffset;
      final int finalInputLen = inputLen;
      final int result =
          nativeKey_.use(
              ptr ->
                  cipher(
                      ptr,
                      mode_,
                      padding_.nativeVal,
                      oaepMdPtr,
                      mgfMdPtr,
                      finalInput,
                      finalInputOffset,
                      finalInputLen,
                      output,
                      outputOffset));

      buffer_ = new AccessibleByteArrayOutputStream();

      return result;
    }
  }

  @Override
  protected int engineGetKeySize(final Key key) throws InvalidKeyException {
    if (key instanceof RSAKey) {
      return ((RSAKey) key).getModulus().bitLength();
    } else {
      throw new InvalidKeyException();
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return 0;
  }

  @Override
  protected byte[] engineGetIV() {
    return null;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    synchronized (lock_) {
      assertInitialized();
      return keySizeBytes_;
    }
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    if (padding_ == Padding.OAEP) {
      try {
        final AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP");
        params.init(oaepParams_);
        return params;
      } catch (final GeneralSecurityException ex) {
        throw new AssertionError(ex);
      }
    } else {
      return null;
    }
  }

  @Override
  protected void engineInit(
      final int opmode,
      final Key key,
      final AlgorithmParameterSpec params,
      final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      if (params instanceof OAEPParameterSpec) {
        if (padding_ != Padding.OAEP) {
          throw new InvalidAlgorithmParameterException();
        }
        final OAEPParameterSpec oaep = (OAEPParameterSpec) params;
        if (!"MGF1".equalsIgnoreCase(oaep.getMGFAlgorithm())
            || oaep.getMGFParameters() == null
            || !(oaep.getMGFParameters() instanceof MGF1ParameterSpec)) {
          throw new InvalidAlgorithmParameterException();
        }
        final PSource pDefault = PSource.PSpecified.DEFAULT;
        final PSource psrc = oaep.getPSource();
        if (psrc == null || !pDefault.getAlgorithm().equalsIgnoreCase(psrc.getAlgorithm())) {
          throw new InvalidAlgorithmParameterException();
        }
        if (!(psrc instanceof PSource.PSpecified)) {
          throw new InvalidAlgorithmParameterException();
        }
        // TODO: support non-empty labels, there's no technical reason not to
        if (((PSource.PSpecified) psrc).getValue().length != 0) {
          throw new InvalidAlgorithmParameterException();
        }
        final MGF1ParameterSpec mgfParams = (MGF1ParameterSpec) oaep.getMGFParameters();
        final MGF1ParameterSpec oldMgfParams = (MGF1ParameterSpec) oaepParams_.getMGFParameters();
        if (!allowParamUpdates_
            && !(oaep.getDigestAlgorithm().equals(oaepParams_.getDigestAlgorithm())
                && mgfParams.getDigestAlgorithm().equals(oldMgfParams.getDigestAlgorithm()))) {
          throw new InvalidAlgorithmParameterException();
        }
      } else {
        throw new InvalidAlgorithmParameterException();
      }
    }

    synchronized (lock_) {
      if (!(key instanceof RSAKey)) {
        throw new InvalidKeyException();
      }
      mode_ = checkMode(opmode, key);

      if (key_ != key) {
        if (nativeKey_ != null) {
          nativeKey_.releaseEphemeral();
          nativeKey_ = null;
        }

        key_ = (RSAKey) key;
        keySizeBytes_ = (key_.getModulus().bitLength() + 7) / 8;
        buffer_ = new AccessibleByteArrayOutputStream(keySizeBytes_, keySizeBytes_);
        nativeKey_ = provider_.translateKey(key, EvpKeyType.RSA);
      }

      if (params instanceof OAEPParameterSpec) {
        // Cache MD struct ptrs, validate digest names, update params + padding len
        final OAEPParameterSpec oaepParams = (OAEPParameterSpec) params;
        final String oaepDigest = oaepParams.getDigestAlgorithm();
        final String mgf1Digest =
            ((MGF1ParameterSpec) oaepParams.getMGFParameters()).getDigestAlgorithm();
        try {
          Utils.getMdPtr(oaepParams.getDigestAlgorithm());
          Utils.getMdPtr(((MGF1ParameterSpec) oaepParams.getMGFParameters()).getDigestAlgorithm());
        } catch (Exception e) {
          throw new InvalidAlgorithmParameterException();
        }
        paddingSize_ = calculateOaepPaddingLen(oaepParams.getDigestAlgorithm());
        oaepParams_ = oaepParams;
      }
    }
  }

  // NOTE: while RFC-2437 stipulates[1] that OAEP padding has max length of 2*digestSize+1,
  //       both standard JCE[2] and AWS-LC[3][4] reserve an extra byte of padding space to
  //       ensure that the size of the padded message does not excede that of the modulus,
  //       hence the +2 in the calculation below.
  //
  // [1]: https://datatracker.ietf.org/doc/html/rfc2437#section-9.1.1.1
  // [2]:
  // https://github.com/corretto/corretto-8/blob/develop/src/jdk/src/share/classes/sun/security/rsa/RSAPadding.java#L191
  // [3]: https://github.com/awslabs/aws-lc/blob/main/crypto/fipsmodule/rsa/padding.c#L349
  // [4]: https://github.com/awslabs/aws-lc/blob/main/crypto/fipsmodule/rsa/padding.c#L420-L427
  private static int calculateOaepPaddingLen(String mdName) {
    return 2 * Utils.getMdLen(Utils.getMdPtr(mdName)) + 2;
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, final AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    try {
      engineInit(
          opmode,
          key,
          params != null ? params.getParameterSpec(OAEPParameterSpec.class) : null,
          random);
    } catch (final InvalidParameterSpecException ex) {
      throw new InvalidAlgorithmParameterException(ex);
    }
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    AlgorithmParameterSpec params = null;
    if (padding_ == Padding.OAEP) {
      params = oaepParams_;
    }
    try {
      engineInit(opmode, key, params, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e);
    }
  }

  /**
   * Checks to ensure that the {@code requestedMode} is appropriate for the provided {@code key} and
   * if it isn't, throws an {@link InvalidKeyException}. The returned mode is the same as {@code
   * requestedMode} <em>unless</em> this cipher is being used in reverse (encrypt with a private
   * key, decrypt with a private), which is done for RSA signature generation. In those cases we
   * convert {@link Cipher#ENCRYPT_MODE} to {@code -1 * Cipher.ENCRYPT_MODE} and {@link
   * Cipher#DECRYPT_MODE} to {@code -1 * Cipher.DECRYPT_MODE}.
   */
  private static int checkMode(int requestedMode, Key key) throws InvalidKeyException {
    if (key instanceof PrivateKey) {
      switch (requestedMode) {
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
          return requestedMode;
        case Cipher.ENCRYPT_MODE:
          return -1 * requestedMode;
        default:
          throw new InvalidKeyException("Private keys not supported for mode " + requestedMode);
      }
    } else if (key instanceof PublicKey) {
      switch (requestedMode) {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
          return requestedMode;
        case Cipher.DECRYPT_MODE:
          return -1 * requestedMode;
        default:
          throw new InvalidKeyException("Public keys not supported for mode " + requestedMode);
      }
    } else {
      throw new InvalidKeyException("Unsupported key type: " + key.getClass());
    }
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    if (!"ECB".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException();
    }
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    if (!padding_.paddingStr.equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException();
    }
  }

  @Override
  protected byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
    synchronized (lock_) {
      assertInitialized();
      buffer_.write(input, inputOffset, inputLen);
    }
    return EMPTY_ARRAY;
  }

  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException {
    synchronized (lock_) {
      assertInitialized();
      buffer_.write(input, inputOffset, inputLen);
    }
    return 0;
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (mode_ != Cipher.UNWRAP_MODE && mode_ != Cipher.DECRYPT_MODE) {
      throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
    }
    try {
      final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(provider_, unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
      throw new InvalidKeyException("Unwrapping failed", ex);
    }
  }

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (mode_ != Cipher.WRAP_MODE && mode_ != Cipher.ENCRYPT_MODE) {
      throw new IllegalStateException("Cipher must be in WRAP_MODE");
    }
    try {
      final byte[] encoded = Utils.encodeForWrapping(provider_, key);
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (final BadPaddingException ex) {
      throw new InvalidKeyException("Wrapping failed", ex);
    }
  }

  private void assertInitialized() {
    synchronized (lock_) {
      if (key_ == null) {
        throw new IllegalStateException();
      }
    }
  }

  static class NoPadding extends RsaCipher {
    NoPadding(AmazonCorrettoCryptoProvider provider) {
      super(provider, Padding.NO_PADDING, 0, false);
    }
  }

  static class Pkcs1 extends RsaCipher {
    Pkcs1(AmazonCorrettoCryptoProvider provider) {
      super(provider, Padding.PKCS1, 11, false);
    }
  }

  static class OAEP extends RsaCipher {
    OAEP(AmazonCorrettoCryptoProvider provider) {
      super(
          provider,
          Padding.OAEP,
          calculateOaepPaddingLen(OAEPParameterSpec.DEFAULT.getDigestAlgorithm()),
          true);
    }
  }

  static class OAEPSha1 extends RsaCipher {
    OAEPSha1(AmazonCorrettoCryptoProvider provider) {
      super(
          provider,
          Padding.OAEP,
          calculateOaepPaddingLen(OAEPParameterSpec.DEFAULT.getDigestAlgorithm()),
          false);
    }
  }
}
