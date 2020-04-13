// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.EMPTY_ARRAY;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
    private static final KeyFactory KEY_FACTORY;

    // From openssl/rsa.h
    private static enum Padding {
        /** PKCS #1 v1.5 */
        PKCS1(1, "PKCS1Padding", 11),
        NO_PADDING(3, "NoPadding", 0),
        /** PKCS #1 v2.0 with SHA-1, MGF1, and an empty encoding parameter */
        OAEP_SHA1_MGF1(4, "OAEPWithSHA-1AndMGF1Padding", 42);

        private final int nativeVal;
        private final String jceName;
        private final int paddingLength;

        private Padding(final int val, final String name, final int length) {
            nativeVal = val;
            jceName = name;
            paddingLength = length;
        }
    }

    static {
        Loader.load();
        try {
            KEY_FACTORY = KeyFactory.getInstance("RSA");
        } catch (final NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        }
    }

    private static native void releaseNativeKey(long ptr);

    private static native int cipher(int mode,
            byte[] input, int inOff, int inLength,
            byte[] output, int outOff,
            int padding,
            boolean checkPrivateKey,
            long[] keyHandle,
            int handleMode,
            byte[] pubExp,
            byte[] modulus,
            byte[] privExp,
            byte[] primeP,
            byte[] primeQ,
            byte[] dmP,
            byte[] dmQ,
            byte[] coef
        );

    private final AmazonCorrettoCryptoProvider provider_;
    private final Object lock_ = new Object();
    private final Padding padding_;

    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    private int mode_;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    private RSAKey key_;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    private int keySizeBytes_;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    private NativeRsaKey nativeKey_;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    private AccessibleByteArrayOutputStream buffer_;
    // KeyParts
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] n;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] e;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] d;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] p;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] q;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] dmp1;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] dmq1;
    // @GuardedBy("lock_") // Restore once replacement for JSR-305 available
    byte[] iqmp;

    // Most cipher object will either be used only once (with a given key)
    // or many times with the same key. To avoid leaving potentially large
    // amounts of native memory allocated for our keys, we only cache the
    // native key after its _second_ use (meaning we do free it after its
    // first). reUseKey_ being false means that we _should_ free the native
    // key after use. reUseKey_ being true means that we should not free the
    // native key after use. In order to achieve our simple caching patterns,
    // whenever we free a key, we set reUseKey_ to true so that the next time
    // we use it, we keep it around. (We also set reUseKey_ to false if the
    // key is changed.)
    private boolean reUseKey_ = false;

    RsaCipher(AmazonCorrettoCryptoProvider provider, final Padding padding) {
        Loader.checkNativeLibraryAvailability();
        provider_ = provider;
        padding_ = padding;
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
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, final byte[] output,
            final int outputOffset)
                    throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        synchronized (lock_) {
            assertInitialized();
            try {
                parseKey();
            } catch (final InvalidKeyException e) {
                throw new IllegalStateException(e);
            }
            if (buffer_.size() != 0) { // Not one-shot
                if (input != null) {
                    buffer_.write(input, inputOffset, inputLen);
                }
                input = buffer_.getDataBuffer();
                inputOffset = 0;
                inputLen = buffer_.size();
            }

            if (output.length - outputOffset < engineGetOutputSize(inputLen)) {
                throw new ShortBufferException();
            }
            if (mode_ == Cipher.ENCRYPT_MODE || mode_ == Cipher.WRAP_MODE) {
                if (inputLen > keySizeBytes_ - padding_.paddingLength) {
                    throw new BadPaddingException("Data must not be longer than "
                            + (keySizeBytes_ - padding_.paddingLength) + " bytes");
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
                    throw new BadPaddingException("Input length is too long.");
                }
            }
            
            final int result;
            if (nativeKey_ != null) {
              result = cipherWithNativeKey(input, inputOffset, inputLen, output, outputOffset);
            } else if (!reUseKey_) {
              result = cipherWithRawParams(input, inputOffset, inputLen, output, outputOffset);
              reUseKey_ = true;
            } else {
              result = cipherAndCreateNativeKey(input, inputOffset, inputLen, output, outputOffset);
            }
            buffer_ = new AccessibleByteArrayOutputStream();

            return result;
        }
    }

    private int cipherWithNativeKey(final byte[] input, final int inputOffset, final int inputLen,
        final byte[] output, final int outputOffset) {
      synchronized (lock_) {
        if (nativeKey_ == null) {
          throw new IllegalStateException("cipherWithNativeKey must only be called with a non-null nativeKey_");
        }
        return nativeKey_.use(ptr ->
          cipher(mode_,
              input, inputOffset, inputLen,
              output, outputOffset,
              padding_.nativeVal,
              provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
              new long[]{ptr}, HANDLE_USAGE_USE,
              null, null, null, null, null, null, null, null));
      }
    }

    private int cipherWithRawParams(final byte[] input, final int inputOffset, final int inputLen,
        final byte[] output, final int outputOffset) {
      synchronized (lock_) {
        return cipher(mode_,
              input, inputOffset, inputLen,
              output, outputOffset,
              padding_.nativeVal,
              provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
              null, HANDLE_USAGE_IGNORE,
              n, e, d, p, q, dmp1, dmq1, iqmp);
      }
    }

    private int cipherAndCreateNativeKey(final byte[] input, final int inputOffset, final int inputLen,
        final byte[] output, final int outputOffset) {
      synchronized (lock_) {
        final long[] tmpPtr = new long[1];
        final int result = cipher(mode_,
              input, inputOffset, inputLen,
              output, outputOffset,
              padding_.nativeVal,
              provider_.hasExtraCheck(ExtraCheck.PRIVATE_KEY_CONSISTENCY),
              tmpPtr, HANDLE_USAGE_CREATE,
              n, e, d, p, q, dmp1, dmq1, iqmp);
        nativeKey_ = new NativeRsaKey(tmpPtr[0]);
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
        if (padding_.equals(Padding.OAEP_SHA1_MGF1)) {
            try {
                final AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP");
                params.init(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
                return params;
            } catch (final GeneralSecurityException ex) {
                throw new AssertionError(ex);
            }
        } else {
            return null;
        }
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final SecureRandom random)
            throws InvalidKeyException {
        synchronized (lock_) {
            if (!(key instanceof RSAKey)) {
                throw new InvalidKeyException();
            }
            mode_ = checkMode(opmode, key);

            if (key_ != key) {
              if (nativeKey_ != null) {
                nativeKey_.release();
                nativeKey_ = null;
              }
              reUseKey_ = false;

              key_ = (RSAKey) key;
              keySizeBytes_ = (key_.getModulus().bitLength() + 7) / 8;
              buffer_ = new AccessibleByteArrayOutputStream();
              parseKey();
          }
        }
    }

    /**
     * Checks to ensure that the {@code requestedMode} is appropriate for the provided {@code key} and if it isn't,
     * throws an {@link InvalidKeyException}. The returned mode is the same as {@code requestedMode} <em>unless</em>
     * this cipher is being used in reverse (encrypt with a private key, decrypt with a private), which is done for
     * RSA signature generation. In those cases we convert {@link Cipher#ENCRYPT_MODE} to
     * {@code -1 * Cipher.ENCRYPT_MODE} and {@link Cipher#DECRYPT_MODE} to {@code -1 * Cipher.DECRYPT_MODE}.
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

    private void parseKey() throws InvalidKeyException {
        synchronized (lock_) {
            if (nativeKey_ != null && !nativeKey_.isReleased()) {
                return;
            }
            n = null;
            e = null;
            d = null;
            p = null;
            q = null;
            dmp1 = null;
            dmq1 = null;
            iqmp = null;
            if (key_ instanceof PrivateKey) {
                boolean parsedKey = false;
                try {
                    final RSAPrivateCrtKeySpec spec = KEY_FACTORY.getKeySpec((Key) key_, RSAPrivateCrtKeySpec.class);
                    n = spec.getModulus().toByteArray();
                    e = spec.getPublicExponent().toByteArray();
                    d = spec.getPrivateExponent().toByteArray();
                    p = spec.getPrimeP().toByteArray();
                    q = spec.getPrimeQ().toByteArray();
                    dmp1 = spec.getPrimeExponentP().toByteArray();
                    dmq1 = spec.getPrimeExponentQ().toByteArray();
                    iqmp = spec.getCrtCoefficient().toByteArray();
                    parsedKey = true;
                } catch (final InvalidKeySpecException e) {
                    // swallow the exception
                }
                if (!parsedKey) {
                    try {
                        final RSAPrivateKeySpec spec = KEY_FACTORY.getKeySpec((Key) key_, RSAPrivateKeySpec.class);
                        n = spec.getModulus().toByteArray();
                        d = spec.getPrivateExponent().toByteArray();
                        parsedKey = true;
                    } catch (final InvalidKeySpecException e) {
                        // swallow the exception
                    }
                }
                if (!parsedKey) {
                    throw new InvalidKeyException("Unable to parse the key " + key_);
                }

            } else if (key_ instanceof PublicKey) {
                try {
                    final RSAPublicKeySpec spec = KEY_FACTORY.getKeySpec((Key) key_, RSAPublicKeySpec.class);
                    n = spec.getModulus().toByteArray();
                    e = spec.getPublicExponent().toByteArray();
                } catch (final InvalidKeySpecException e) {
                    throw new InvalidKeyException(e);
                }
            } else {
                throw new IllegalArgumentException("Unexpected key type: " + key_.getClass());
            }
        }
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameterSpec params,
            final SecureRandom random)
                    throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            if (params instanceof OAEPParameterSpec && padding_.equals(Padding.OAEP_SHA1_MGF1)) {
                final OAEPParameterSpec oaep = (OAEPParameterSpec) params;
                if (!"SHA-1".equalsIgnoreCase(oaep.getDigestAlgorithm()) ||
                        !"MGF1".equalsIgnoreCase(oaep.getMGFAlgorithm()) ||
                        oaep.getMGFParameters() == null ||
                        !(oaep.getMGFParameters() instanceof MGF1ParameterSpec)) {
                    throw new InvalidAlgorithmParameterException();
                }
                final MGF1ParameterSpec mgf = (MGF1ParameterSpec) oaep.getMGFParameters();
                if (!MGF1ParameterSpec.SHA1.getDigestAlgorithm().equals(mgf.getDigestAlgorithm())) {
                    throw new InvalidAlgorithmParameterException();
                }
                final PSource pDefault = PSource.PSpecified.DEFAULT;
                final PSource psrc = oaep.getPSource();
                if (psrc == null || !pDefault.getAlgorithm().equalsIgnoreCase(psrc.getAlgorithm())) {
                    throw new InvalidAlgorithmParameterException();
                }
            } else {
                throw new InvalidAlgorithmParameterException();
            }
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(final int opmode, final Key key, final AlgorithmParameters params,
            final SecureRandom random)
                    throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            engineInit(opmode, key, params.getParameterSpec(OAEPParameterSpec.class), random);
        } catch (final InvalidParameterSpecException ex) {
            throw new InvalidAlgorithmParameterException(ex);
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
        if (!padding_.jceName.equalsIgnoreCase(padding)) {
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
    protected int engineUpdate(final byte[] input, final int inputOffset, final int inputLen,
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
    protected Key engineUnwrap(final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (mode_ != Cipher.UNWRAP_MODE && mode_ != Cipher.DECRYPT_MODE) {
            throw new IllegalStateException("Cipher must be in UNWRAP_MODE");
        }
        try {
            final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return Utils.buildUnwrappedKey(unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
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
            final byte[] encoded = Utils.encodeForWrapping(key);
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

    private static class NativeRsaKey extends NativeResource {
        protected NativeRsaKey(final long ptr) {
            super(ptr, RsaCipher::releaseNativeKey);
        }
    }

    static class NoPadding extends RsaCipher {
        NoPadding(AmazonCorrettoCryptoProvider provider) {
            super(provider, Padding.NO_PADDING);
        }
    }

    static class Pkcs1 extends RsaCipher {
        Pkcs1(AmazonCorrettoCryptoProvider provider) {
            super(provider, Padding.PKCS1);
        }
    }

    static class OAEPSha1 extends RsaCipher {
        OAEPSha1(AmazonCorrettoCryptoProvider provider) {
            super(provider, Padding.OAEP_SHA1_MGF1);
        }
    }
}
