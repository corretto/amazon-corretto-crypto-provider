// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;

/**
 * An HPKE recipient private key. See {@link HpkeKey} for suite binding and encoding rules.
 *
 * @serial exclude
 */
public final class HpkePrivateKey extends HpkeKey implements PrivateKey, Destroyable {
  static {
    Loader.load();
  }

  private static native long nativeGenerate(int kemId, int kdfId, int aeadId);

  private static native long nativeImport(int kemId, int kdfId, int aeadId, byte[] seed)
      throws InvalidKeyException;

  private static native byte[] nativeGetPublicKey(long ptr);

  private static native byte[] nativeGetPrivateKey(long ptr);

  private static native void nativeRelease(long ptr);

  // Owns the native EVP_HPKE_KEY. Seed exports are fresh native copies, never cached on the heap.
  private final InternalKey internalKey;
  private volatile boolean isDestroyed = false;

  private HpkePrivateKey(final HpkeSuite suite, final long ptr) {
    super(suite);
    this.internalKey = new InternalKey(ptr);
  }

  /** Takes ownership of a native key, freeing it if the wrapper cannot be created. */
  private static HpkePrivateKey wrap(final HpkeSuite suite, final long ptr) {
    try {
      return new HpkePrivateKey(suite, ptr);
    } catch (final Throwable t) {
      nativeRelease(ptr);
      throw t;
    }
  }

  static HpkePrivateKey generate(final HpkeSuite suite) {
    Loader.checkNativeLibraryAvailability();
    return wrap(suite, nativeGenerate(suite.kemId, suite.kdfId, suite.aeadId));
  }

  /**
   * Imports the seed encoding described in {@link HpkeKey} for {@code spec}'s suite ids. Info and
   * encapsulation are ignored; {@code seed} is neither retained nor modified.
   *
   * @param spec the suite parameters
   * @param seed the 64-byte FIPS 203 private seed ({@code d || z})
   * @return the imported recipient private key
   * @throws InvalidKeyException if the suite is not one that the linked AWS-LC provides, or {@code
   *     seed} has the wrong length or is rejected by AWS-LC
   * @throws IllegalArgumentException if {@code spec} or {@code seed} is null
   */
  public static HpkePrivateKey fromEncoded(final HpkeParameterSpec spec, final byte[] seed)
      throws InvalidKeyException {
    final HpkeSuite s = importSuite(spec);
    Utils.requireNonNull(seed, "seed must not be null");
    if (seed.length != s.privateKeyLength()) {
      throw new InvalidKeyException(
          "HPKE private key (seed) must be " + s.privateKeyLength() + " bytes for this suite");
    }
    return wrap(s, nativeImport(s.kemId, s.kdfId, s.aeadId, seed));
  }

  /**
   * Derives the matching public key for the same suite; it is valid without an import check.
   *
   * @return the recipient public key
   * @throws IllegalStateException if this key has been destroyed
   */
  public HpkePublicKey getPublicKey() {
    return new HpkePublicKey(suite(), use(HpkePrivateKey::nativeGetPublicKey));
  }

  /**
   * Returns a fresh copy of the 64-byte private seed.
   *
   * @throws IllegalStateException if this key has been destroyed
   */
  @Override
  public byte[] getEncoded() {
    return use(HpkePrivateKey::nativeGetPrivateKey);
  }

  /** Calls {@code function} with the native {@code EVP_HPKE_KEY*}, while keeping it alive. */
  <T, X extends Throwable> T use(final MiscInterfaces.ThrowingLongFunction<T, X> function)
      throws X {
    assertNotDestroyed();
    return internalKey.use(function);
  }

  private void assertNotDestroyed() {
    if (isDestroyed) {
      throw new IllegalStateException("Key has been destroyed");
    }
  }

  /** Returns whether {@link #destroy()} has been called. */
  @Override
  public boolean isDestroyed() {
    return isDestroyed;
  }

  /**
   * Frees and cleanses the private key material. Subsequent {@link #getEncoded()} and {@link
   * #getPublicKey()} calls throw {@link IllegalStateException}; HPKE Cipher initialization reports
   * the destroyed key as {@link InvalidKeyException}. Public keys and Cipher contexts already
   * derived from this key remain usable.
   *
   * @throws IllegalStateException if this key has already been destroyed
   */
  @Override
  public synchronized void destroy() {
    assertNotDestroyed();
    isDestroyed = true;
    internalKey.release();
  }

  /**
   * Compares HPKE private keys by suite and seed, comparing seeds in constant time and wiping the
   * temporary copies.
   *
   * <p>Comparison with this instance returns true, even after destruction. Comparison with another
   * type or suite returns false without accessing either seed.
   *
   * @throws IllegalStateException if comparing distinct keys of the same suite and either has been
   *     destroyed
   */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof HpkePrivateKey)) {
      return false;
    }
    final HpkePrivateKey other = (HpkePrivateKey) obj;
    if (suite() != other.suite()) {
      return false;
    }
    byte[] mine = null;
    byte[] theirs = null;
    try {
      mine = getEncoded();
      theirs = other.getEncoded();
      return ConstantTime.equals(mine, theirs);
    } finally {
      if (mine != null) {
        Arrays.fill(mine, (byte) 0);
      }
      if (theirs != null) {
        Arrays.fill(theirs, (byte) 0);
      }
    }
  }

  /** Returns the suite's KEM id, without accessing the seed, even after destruction. */
  @Override
  public int hashCode() {
    return suite().kemId;
  }

  private static final class InternalKey extends NativeResource {
    InternalKey(final long ptr) {
      // EVP_HPKE_KEY is read-only after creation, so concurrent use is safe.
      super(ptr, HpkePrivateKey::nativeRelease, true);
    }
  }
}
