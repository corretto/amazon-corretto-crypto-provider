// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static java.util.logging.Logger.getLogger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;

abstract class EvpKeyPairGenerator extends KeyPairGeneratorSpi {

  private final AmazonCorrettoCryptoProvider provider;
  private final KeyFactory keyFactory;
  protected final EvpKeyType evpKeyType;

  EvpKeyPairGenerator(AmazonCorrettoCryptoProvider provider, EvpKeyType evpKeyType) {
    Loader.checkNativeLibraryAvailability();
    this.provider = provider;
    this.evpKeyType = evpKeyType;
    this.keyFactory = getKeyFactory();
  }

  @Override
  public void initialize(final int keysize, final SecureRandom random) {
    // No-op for compatibility with callers (e.g. BouncyCastle TLS) that invoke
    // initialize(int, SecureRandom) before generateKeyPair(). The keysize is
    // fixed by the underlying algorithm, so there is nothing to configure, and
    // ACCP's generator always uses libcrypto's DRBG regardless of |random|.
    // Note: initialize(AlgorithmParameterSpec, SecureRandom) inherits the default
    // SPI impl (throws UnsupportedOperationException) unless a subclass overrides
    // it (e.g. XDHGen accepts NamedParameterSpec.X25519).
  }

  // Provides an appropriate KeyFactory for this key type
  protected abstract KeyFactory getKeyFactory();

  // Generates a private key of `evpKeyType`, taking over ownership of the given native key
  protected abstract PrivateKey getPrivateKey(EvpKey.InternalKey key);

  // Generates a public key of `evpKeyType`, from the private key
  protected abstract PublicKey getPublicKey(PrivateKey privateKey);

  // Generates a new EVP key based on the given native Key ID
  // and returns a pointer to it encoded as a java |long|
  private static native long generateEvpKey(int nativeKeyId);

  @Override
  public KeyPair generateKeyPair() {
    // Wrapped first so that every failure below has an owner that can release the native key.
    final EvpKey.InternalKey nativeKey =
        new EvpKey.InternalKey(generateEvpKey(evpKeyType.nativeValue));
    PrivateKey privateKey = null;
    final PublicKey publicKey;
    try {
      privateKey = getPrivateKey(nativeKey);
      // Takes a reference of its own on the native key, and can fail doing so.
      publicKey = getPublicKey(privateKey);
    } catch (final RuntimeException | Error e) {
      destroyQuietly((EvpKey) privateKey);
      nativeKey.release();
      throw e;
    }
    if (keyFactory == null) {
      // This case indicates situations where a KeyFactory is not available
      // for this key type due to JDK incompatibility or JCA provider issues.
      // The caller receives ACCP's own keys and owns them from here.
      return new KeyPair(publicKey, privateKey);
    }
    try {
      final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKey.getEncoded());
      final PrivateKey jcePrivateKey = keyFactory.generatePrivate(privateKeyPkcs8);
      final PublicKey jcePublicKey = keyFactory.generatePublic(publicKeyX509);
      return new KeyPair(jcePublicKey, jcePrivateKey);
    } catch (final GeneralSecurityException e) {
      throw new RuntimeException("Error generating key pair", e);
    } finally {
      // The caller only sees the JCE keys built above, so nothing can reach these two again and
      // the native keys would otherwise sit in the janitor until the next GC.
      destroyQuietly((EvpKey) privateKey);
      destroyQuietly((EvpKey) publicKey);
    }
  }

  // Releasing one key must neither skip the other nor replace an exception already on its way to
  // the caller. |key| is null when generation failed before it was built.
  private static void destroyQuietly(final EvpKey key) {
    if (key == null) {
      return;
    }
    try {
      key.destroy();
    } catch (final RuntimeException e) {
      getLogger("AmazonCorrettoCryptoProvider")
          .log(Level.WARNING, "Could not release a generated key", e);
    }
  }
}
