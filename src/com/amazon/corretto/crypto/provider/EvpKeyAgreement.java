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
    // The requested algorithm is resolved before the agreed secret is consumed: the no-arg
    // engineGenerateSecret() calls reset(), so rejecting a name afterwards would destroy the secret
    // too, breaking both the reuse documented in DIFFERENCES.md and any caller that tries one
    // output algorithm name and falls back to another. SunEC validates first for the same reason.
    if (algorithm == null) {
      throw new NoSuchAlgorithmException("Algorithm must not be null");
    }
    if (algorithm.equalsIgnoreCase("TlsPremasterSecret")) {
      return new SecretKeySpec(engineGenerateSecret(), "TlsPremasterSecret");
    }
    // Both "com/sun/crypto/provider/DHKEM.java" (backing HPKE and the "DHKEM"
    // KEM) and "sun/security/ssl/DHasKEM.java" (the classical half of TLS 1.3
    // hybrid key exchange, e.g. X25519MLKEM768) obtain the raw agreed secret via
    // generateSecret("Generic"), "Generic" being the default output algorithm of
    // the javax.crypto.KEM API. Neither pins a provider when requesting
    // ECDH/XDH, so ACCP wins the service and must accept "Generic" or it breaks
    // HPKE and TLS handshakes for anyone who installs it. JTREG test
    // "sun/security/ssl/HybridKeyExchange/TestHybrid.java" drives that path.
    if (algorithm.equalsIgnoreCase("Generic")) {
      return new SecretKeySpec(engineGenerateSecret(), "Generic");
    }
    // NoSuchAlgorithmException rather than InvalidKeyException for an unavailable output algorithm:
    // that is what KeyAgreement.generateSecret(String) documents and what SunEC throws, so a caller
    // that catches it to fall back to generateSecret() + SecretKeySpec still gets its fallback.
    final Matcher matcher = ALGORITHM_WITH_EXPLICIT_KEYSIZE.matcher(algorithm);
    if (!matcher.matches()) {
      throw new NoSuchAlgorithmException("Unrecognized algorithm: " + algorithm);
    }
    if (!"AES".equals(matcher.group(1))) {
      throw new NoSuchAlgorithmException("Unsupported algorithm: " + matcher.group(1));
    }
    final String keySizeString = matcher.group(2);
    int keyLength = 0;
    if (keySizeString != null) {
      try {
        keyLength = Integer.parseInt(keySizeString);
      } catch (final NumberFormatException e) {
        // The pattern admits digit strings too long for an int.
        throw new InvalidKeyException("Invalid key length", e);
      }
      if (!isAesKeySize(keyLength)) {
        throw new InvalidKeyException("Invalid key length");
      }
    }
    final byte[] secret = engineGenerateSecret();
    if (keySizeString == null) {
      // Largest AES key the agreed secret can supply.
      for (final int aesLength : AES_KEYSIZES_BYTES) {
        if (aesLength <= secret.length) {
          keyLength = aesLength;
        }
      }
    }
    if (keyLength == 0 || keyLength > secret.length) {
      throw new InvalidKeyException("Invalid key length");
    }
    return new SecretKeySpec(secret, 0, keyLength, "AES");
  }

  private static boolean isAesKeySize(final int lengthBytes) {
    for (final int aesLength : AES_KEYSIZES_BYTES) {
      if (aesLength == lengthBytes) {
        return true;
      }
    }
    return false;
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
    // If the following key translation throws an exception,
    // then `key` must be invalid and we must not retain the `privKey` value
    // to conform with JCE as described in JTREG test
    // "sun/security/ec/ECDHKeyAgreementParamValidation.java".
    privKey = null;
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

  static class XDH extends EvpKeyAgreement {
    XDH(AmazonCorrettoCryptoProvider provider) {
      super(provider, "XDH", EvpKeyType.XDH);
    }
  }
}
