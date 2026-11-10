// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 * Base class for ACCP's HPKE recipient public and private keys.
 *
 * <p>Keys are bound to a whole suite (KEM, KDF and AEAD). {@link #parameterSpec()} returns its
 * named constant; the Cipher requires the same suite.
 *
 * <p>The HPKE Cipher accepts only {@link HpkePublicKey} and {@link HpkePrivateKey}; other ciphers
 * reject these keys.
 *
 * <p>{@code "RAW"} encodes the public key bytes or the 64-byte FIPS 203 private seed ({@code d ||
 * z}). Importing and exporting only seeds prevents mismatched seed/expanded-key pairs. Import with
 * {@link HpkePublicKey#fromEncoded} or {@link HpkePrivateKey#fromEncoded}.
 *
 * <p>HPKE keys cannot be serialized, so that a private seed never leaves through an object stream;
 * use {@code getEncoded()} and {@code fromEncoded}.
 *
 * @serial exclude
 */
public abstract class HpkeKey implements Key {
  private final HpkeSuite suite;

  HpkeKey(final HpkeSuite suite) {
    this.suite = Utils.requireNonNull(suite, "suite must not be null");
  }

  /** The curated suite this key is bound to. */
  final HpkeSuite suite() {
    return suite;
  }

  /** Resolves import suite ids, ignoring info and encapsulation; see {@link HpkeSuite#require}. */
  static HpkeSuite importSuite(final HpkeParameterSpec spec) throws InvalidKeyException {
    Utils.requireNonNull(spec, "spec must not be null");
    Loader.checkNativeLibraryAvailability();
    try {
      return HpkeSuite.require(spec.kem_id(), spec.kdf_id(), spec.aead_id());
    } catch (final InvalidAlgorithmParameterException ex) {
      throw new InvalidKeyException(ex.getMessage(), ex);
    }
  }

  /**
   * Returns the named {@link HpkeParameterSpec} constant for this key's suite (base mode, empty
   * {@code info}, no encapsulation), e.g. for {@code key.parameterSpec().withEncapsulation(enc)}.
   *
   * @return this key's suite parameters
   */
  public final HpkeParameterSpec parameterSpec() {
    return suite.spec();
  }

  /**
   * Returns this suite's KEM encapsulation length in bytes for framing {@code enc} and ciphertext.
   *
   * @return the encapsulation length in bytes
   */
  public final int encapsulationLength() {
    return suite.encLength();
  }

  /** Returns {@code "HPKE"}. */
  @Override
  public String getAlgorithm() {
    return "HPKE";
  }

  /** Returns {@code "RAW"}. */
  @Override
  public String getFormat() {
    return "RAW";
  }

  private void writeObject(final ObjectOutputStream out) throws IOException {
    throw new NotSerializableException("HpkeKey");
  }

  private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    throw new NotSerializableException("HpkeKey");
  }

  private void readObjectNoData() throws ObjectStreamException {
    throw new NotSerializableException("HpkeKey");
  }
}
