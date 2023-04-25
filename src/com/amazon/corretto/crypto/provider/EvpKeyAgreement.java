// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

class EvpKeyAgreement extends KeyAgreementSpi {
  private static final int[] AES_KEYSIZES_BYTES = new int[] {16, 24, 32};
  private static final Pattern ALGORITHM_WITH_EXPLICIT_KEYSIZE =
      Pattern.compile("(\\S+?)(?:\\[(\\d+)\\])?");

  private final AmazonCorrettoCryptoProvider provider_;
  private final EvpKeyType keyType_;
  private final String algorithm_;
  private EvpKey privKey = null;
  private byte[] secret = null;

  private static native byte[] agree(long privateKeyPtr, long publicKeyPtr)
      throws InvalidKeyException;

  EvpKeyAgreement(
      AmazonCorrettoCryptoProvider provider, final String algorithm, final EvpKeyType keyType) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    algorithm_ = algorithm;
    keyType_ = keyType;
  }

  private byte[] agree(EvpKey pubKey) throws InvalidKeyException {
    return privKey.use(privatePtr -> pubKey.use(publicPtr -> agree(privatePtr, publicPtr)));
  }

  @Override
  protected Key engineDoPhase(final Key key, final boolean lastPhase)
      throws InvalidKeyException, IllegalStateException {
    if (privKey == null) {
      throw new IllegalStateException("KeyAgreement has not been initialized");
    }

    if (!keyType_.publicKeyClass.isAssignableFrom(key.getClass())) {
      throw new InvalidKeyException(
          "Expected key of type " + keyType_.publicKeyClass + " not " + key.getClass());
    }
    final EvpKey publicKey = provider_.translateKey(key, keyType_);
    try {
      if (lastPhase) {
        // We do the actual agreement here because that is where key validation and thus exceptions
        // get thrown.
        secret = agree(publicKey);
        return null;
      } else {
        secret = null;
        throw new IllegalStateException("Only single phase agreement is supported");
      }
    } finally {
      publicKey.releaseEphemeral();
    }
  }

  @Override
  protected byte[] engineGenerateSecret() throws IllegalStateException {
    if (privKey == null) {
      throw new IllegalStateException("KeyAgreement has not been initialized");
    }
    if (secret == null) {
      throw new IllegalStateException("KeyAgreement has not been completed");
    }
    final byte[] result = secret;
    reset();
    return result;
  }

  @Override
  protected SecretKey engineGenerateSecret(final String algorithm)
      throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
    byte[] secret = engineGenerateSecret();
    if (algorithm.equalsIgnoreCase("TlsPremasterSecret")) {
      return new SecretKeySpec(secret, "TlsPremasterSecret");
    }
    ;
    final Matcher matcher = ALGORITHM_WITH_EXPLICIT_KEYSIZE.matcher(algorithm);
    if (matcher.matches()) {
      switch (matcher.group(1)) {
        case "AES":
          String keySizeString = matcher.group(2);
          int keyLength = 0;
          boolean lengthFound = false;
          if (keySizeString != null) {
            keyLength = Integer.parseInt(keySizeString);
            for (final int aesLength : AES_KEYSIZES_BYTES) {
              if (aesLength == keyLength) {
                lengthFound = true;
                break;
              }
            }
          } else {
            for (final int aesLength : AES_KEYSIZES_BYTES) {
              if (aesLength <= secret.length) {
                keyLength = aesLength;
                lengthFound = true;
              }
            }
          }
          if (!lengthFound || keyLength > secret.length) {
            throw new InvalidKeyException("Invalid key length");
          }
          return new SecretKeySpec(secret, 0, keyLength, "AES");

        default:
          throw new InvalidKeyException("Unsupported algorithm: " + matcher.group(1));
      }
    }
    throw new InvalidKeyException("Unrecognized algorithm: " + algorithm);
  }

  @Override
  protected int engineGenerateSecret(final byte[] sharedSecret, final int offset)
      throws IllegalStateException, ShortBufferException {
    final byte[] tmp = engineGenerateSecret();
    if (sharedSecret.length - offset < tmp.length) {
      throw new ShortBufferException();
    }
    System.arraycopy(tmp, 0, sharedSecret, offset, tmp.length);
    reset();
    return tmp.length;
  }

  @Override
  protected void engineInit(final Key key, final SecureRandom ignored) throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("Key must not be null");
    }
    if (!keyType_.privateKeyClass.isAssignableFrom(key.getClass())) {
      throw new InvalidKeyException(
          "Expected key of type " + keyType_.privateKeyClass + " not " + key.getClass());
    }
    if (privKey != null) {
      privKey.releaseEphemeral();
    }
    privKey = provider_.translateKey(key, keyType_);
    reset();
  }

  @Override
  protected void engineInit(
      final Key key, final AlgorithmParameterSpec spec, final SecureRandom ignored)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (spec != null) {
      throw new InvalidAlgorithmParameterException("No algorithm parameter spec expected");
    }
    engineInit(key, ignored);
  }

  protected void reset() {
    secret = null;
  }

  static class ECDH extends EvpKeyAgreement {
    ECDH(AmazonCorrettoCryptoProvider provider) {
      super(provider, "ECDH", EvpKeyType.EC);
    }
  }
}
