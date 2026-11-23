// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;

/**
 * A PBKDF2 key that keeps the inputs it was derived from, so a {@link javax.crypto.spec.PBEKeySpec}
 * can be recovered from it and so PBE services can re-derive from it.
 *
 * <p>Retaining the password is what the {@link PBEKey} contract requires, and it is why this class
 * supports {@link #destroy()}.
 */
final class Pbkdf2Key implements PBEKey {
  private static final long serialVersionUID = 1;

  private final String algorithm;
  private final char[] password;
  private final byte[] salt;
  private final int iterationCount;
  private final byte[] key;
  private volatile boolean isDestroyed = false;

  // Callers zero the buffers they pass once construction returns, so copy them.
  Pbkdf2Key(
      final String algorithm,
      final char[] password,
      final byte[] salt,
      final int iterationCount,
      final byte[] key) {
    this.algorithm = algorithm;
    this.password = password.clone();
    this.salt = salt.clone();
    this.iterationCount = iterationCount;
    this.key = key.clone();
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    assertNotDestroyed();
    return key.clone();
  }

  @Override
  public char[] getPassword() {
    assertNotDestroyed();
    return password.clone();
  }

  @Override
  public byte[] getSalt() {
    assertNotDestroyed();
    return salt.clone();
  }

  @Override
  public int getIterationCount() {
    assertNotDestroyed();
    return iterationCount;
  }

  @Override
  public boolean isDestroyed() {
    return isDestroyed;
  }

  /** Idempotent, so callers can clear the key from a finally block without guarding. */
  @Override
  public synchronized void destroy() {
    isDestroyed = true;
    Arrays.fill(password, '\0');
    Arrays.fill(key, (byte) 0);
  }

  private void assertNotDestroyed() {
    if (isDestroyed) {
      throw new IllegalStateException("Key has been destroyed");
    }
  }

  /**
   * Matches {@link javax.crypto.SecretKey}: equal algorithm, RAW format and encoding.
   *
   * <p>Reads the derived bytes without the destroyed check that the accessors apply, so a destroyed
   * key stays usable as a map key.
   */
  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof SecretKey)) {
      return false;
    }
    final SecretKey other = (SecretKey) obj;
    if (!algorithm.equalsIgnoreCase(other.getAlgorithm())
        || !"RAW".equalsIgnoreCase(other.getFormat())) {
      return false;
    }
    final byte[] otherEncoded = other.getEncoded();
    if (otherEncoded == null) {
      return false;
    }
    try {
      return MessageDigest.isEqual(key, otherEncoded);
    } finally {
      Arrays.fill(otherEncoded, (byte) 0);
    }
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(key) ^ algorithm.toLowerCase(Locale.ROOT).hashCode();
  }

  // Serialize as the derived bytes alone so the password never reaches the stream. KeyRep
  // deserializes to a SecretKeySpec, which cannot round-trip to a PBEKeySpec.
  private Object writeReplace() throws ObjectStreamException {
    return new KeyRep(KeyRep.Type.SECRET, getAlgorithm(), getFormat(), getEncoded());
  }

  private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    throw new InvalidObjectException("Pbkdf2Key cannot be deserialized directly");
  }

  private void readObjectNoData() throws ObjectStreamException {
    throw new InvalidObjectException("Pbkdf2Key cannot be deserialized directly");
  }
}
