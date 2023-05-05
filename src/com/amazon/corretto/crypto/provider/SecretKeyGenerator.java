// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import javax.crypto.Cipher;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class SecretKeyGenerator extends KeyGeneratorSpi {
  private final Supplier<SecureRandom> defaultSecureRandomSupplier;
  private final SecretKeyProperties secretKeyProperties;
  private Optional<SecureRandom> secureRandom;
  private int keySize;

  // This class is instantiated internally by ACCP, and it expects non-null arguments; moreover,
  // defaultSecureRandomSupplier.get() cannot return null.
  SecretKeyGenerator(
      final Supplier<SecureRandom> defaultSecureRandomSupplier,
      final SecretKeyProperties secretKeyProperties) {
    this.defaultSecureRandomSupplier = defaultSecureRandomSupplier;
    this.secretKeyProperties = secretKeyProperties;
    this.secureRandom = Optional.empty();
    this.keySize = secretKeyProperties.defaultKeySize();
  }

  @Override
  protected void engineInit(final SecureRandom random) {
    secureRandom = Optional.ofNullable(random);
  }

  @Override
  protected void engineInit(final AlgorithmParameterSpec params, final SecureRandom random)
      throws InvalidAlgorithmParameterException {
    throw new InvalidAlgorithmParameterException(
        "SecretKeyGenerator does not support initialization with AlgorithmParameterSpec.");
  }

  @Override
  protected void engineInit(final int keySize, final SecureRandom random) {
    secretKeyProperties.checkKeySizeIsValid(keySize);
    this.keySize = keySize;
    this.secureRandom = Optional.ofNullable(random);
  }

  @Override
  protected SecretKey engineGenerateKey() {
    final byte[] keyBytes = new byte[keySize / 8];
    final SecureRandom srand = secureRandom.orElseGet(defaultSecureRandomSupplier);
    srand.nextBytes(keyBytes);
    final SecretKeySpec result = new SecretKeySpec(keyBytes, secretKeyProperties.getName());
    Arrays.fill(keyBytes, (byte) 0);
    return result;
  }

  static final class DefaultSecureRandomSupplier implements Supplier<SecureRandom> {

    private DefaultSecureRandomSupplier() {
      // no op
    }

    public static final DefaultSecureRandomSupplier INSTANCE = new DefaultSecureRandomSupplier();

    @Override
    public SecureRandom get() {
      return new LibCryptoRng();
    }
  }

  /**
   * For each type of secret key, we need to implement this interface and pass an instance of it to
   * SecretKeyGenerator to get a service (SPI) class.
   */
  private interface SecretKeyProperties {
    String getName(); // the name of the algorithm, like AES

    int defaultKeySize(); // the default key size, in bits, to be used in case a key size is not
    // provided

    void checkKeySizeIsValid(
        int keySize); // throws an exception if the given algorithm does not support keys of
    // "keySize"
  }

  static final class AesSecretKeyProperties implements SecretKeyProperties {

    private AesSecretKeyProperties() {
      // no op
    }

    public static final AesSecretKeyProperties INSTANCE = new AesSecretKeyProperties();
    private static final String NAME = "AES";

    private static final Set<Integer> AES_VALID_KEY_SIZES = aesValidKeySizes();

    private static Set<Integer> aesValidKeySizes() {
      final Set<Integer> result = new HashSet<>();
      result.add(128);
      result.add(192);
      result.add(256);
      return result;
    }

    @Override
    public String getName() {
      return NAME;
    }

    @Override
    public int defaultKeySize() {
      try {
        return Math.min(256, Cipher.getMaxAllowedKeyLength("AES"));
      } catch (final NoSuchAlgorithmException e) {
        throw new AssertionError("This is an impossible case.", e);
      }
    }

    @Override
    public void checkKeySizeIsValid(final int keySize) {
      if (!AES_VALID_KEY_SIZES.contains(keySize)) {
        throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
      }
    }
  }

  static KeyGeneratorSpi createAesKeyGeneratorSpi() {
    return new SecretKeyGenerator(
        DefaultSecureRandomSupplier.INSTANCE, AesSecretKeyProperties.INSTANCE);
  }
}
