// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A {@link SecretKey} that holds raw key material in a byte array which the consumer can actively
 * zero out via {@link #destroy()}.
 *
 * <p>Unlike {@link javax.crypto.spec.SecretKeySpec}, whose {@link #destroy()} is a no-op that
 * throws {@link javax.security.auth.DestroyFailedException}, this class implements {@code
 * destroy()} to overwrite the internal byte array with zeros and mark the instance unusable. After
 * destruction, {@link #getEncoded()} and {@link #getAlgorithm()} throw {@link
 * IllegalStateException}.
 *
 * <p>This class is used for symmetric keys whose material the consumer may want to wipe
 * deterministically rather than wait for garbage collection -- for example, ML-KEM shared secrets
 * that will be used as wrapping keys for higher-value material.
 *
 * <p>Instances are not serializable: {@link SecretKey} extends {@link java.io.Serializable}, but
 * serializing a destroyable key would silently copy the raw bytes outside the JVM, defeating the
 * purpose. {@code writeObject}/{@code readObject} throw {@link NotSerializableException}.
 */
final class DestroyableSecretKey implements SecretKey, Destroyable {
  private static final long serialVersionUID = 1L;

  private final String algorithm;
  // not final: bytes cleared on destroy() via Arrays.fill
  private final byte[] key;
  private volatile boolean destroyed;

  DestroyableSecretKey(final byte[] key, final String algorithm) {
    Objects.requireNonNull(key, "key must not be null");
    Objects.requireNonNull(algorithm, "algorithm must not be null");
    if (algorithm.isEmpty()) {
      throw new IllegalArgumentException("algorithm must not be empty");
    }
    if (key.length == 0) {
      throw new IllegalArgumentException("key must not be empty");
    }
    this.algorithm = algorithm;
    this.key = key.clone();
  }

  // getAlgorithm() and getEncoded() share destroy()'s monitor to close a TOCTOU window:
  // without synchronization, a reader can pass assertNotDestroyed() before a concurrent
  // destroy() runs, then read zeros (or partial zeros) after Arrays.fill completes,
  // returning a corrupted key without throwing. Holding the lock guarantees readers either
  // observe destroyed==false and a fully-intact key or destroyed==true and throw.
  @Override
  public synchronized String getAlgorithm() {
    assertNotDestroyed();
    return algorithm;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public synchronized byte[] getEncoded() {
    assertNotDestroyed();
    return key.clone();
  }

  @Override
  public synchronized void destroy() {
    assertNotDestroyed();
    Arrays.fill(key, (byte) 0);
    destroyed = true;
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  private void assertNotDestroyed() {
    if (destroyed) {
      throw new IllegalStateException("Key has been destroyed");
    }
  }

  // equals() and hashCode() are intentionally not overridden. SecretKeySpec compares by
  // (algorithm, key bytes) -- a value-based identity. We diverge for two reasons:
  //   1. After destroy(), the key bytes are zero; equals-by-content would silently report
  //      destroyed instances as equal to a fresh all-zero key, which is a misleading and
  //      potentially security-relevant lie.
  //   2. A content-based hashCode forces us to read the key bytes, which is both a
  //      pointless perf hit on every hash and another place that would need destroy-state
  //      synchronization.
  // Identity-based equality (Object.equals) is the safer default for stateful keys.

  // Block serialization. SecretKey extends Serializable, but emitting the raw key bytes
  // in a serialized form would defeat the destroyable contract.
  private void writeObject(final ObjectOutputStream out) throws IOException {
    throw new NotSerializableException("DestroyableSecretKey");
  }

  private void readObject(final ObjectInputStream in) throws IOException {
    throw new NotSerializableException("DestroyableSecretKey");
  }
}
