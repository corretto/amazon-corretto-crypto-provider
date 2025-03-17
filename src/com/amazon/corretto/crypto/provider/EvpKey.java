// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.Destroyable;

abstract class EvpKey implements Key, Destroyable {
  private static final long serialVersionUID = 1;

  protected final InternalKey internalKey;
  protected final EvpKeyType type;
  protected final boolean isPublicKey;

  /**
   * Indicates that the backing native key is used by another java object and thus must not be
   * released by this one.
   */
  protected boolean sharedKey = false;

  /**
   * Indicates that this key is entirely managed within ACCP controlled code and thus we know when
   * we're done with it and can release it.
   */
  protected boolean ephemeral = false;

  private volatile boolean isDestroyed = false;
  protected volatile byte[] encoded;
  protected volatile Integer cachedHashCode;

  private static native void releaseKey(long ptr);

  private static native byte[] encodePublicKey(long ptr);

  private static native byte[] encodePrivateKey(long ptr);

  protected static native byte[] getDerEncodedParams(long ptr);

  EvpKey(final InternalKey key, final EvpKeyType type, final boolean isPublicKey) {
    Loader.checkNativeLibraryAvailability();
    this.internalKey = key;
    this.type = type;
    this.isPublicKey = isPublicKey;
  }

  boolean isEphemeral() {
    return ephemeral;
  }

  void setEphemeral(final boolean ephemeral) {
    this.ephemeral = ephemeral;
  }

  void releaseEphemeral() {
    if (ephemeral) {
      destroy();
    }
  }

  // @CheckReturnValue // Restore once replacement for JSR-305 available
  <T, X extends Throwable> T use(final MiscInterfaces.ThrowingLongFunction<T, X> function)
      throws X {
    assertNotDestroyed();
    return internalKey.use(function);
  }

  <X extends Throwable> void useVoid(final MiscInterfaces.ThrowingLongConsumer<X> function)
      throws X {
    assertNotDestroyed();
    internalKey.useVoid(function);
  }

  @Override
  public String getAlgorithm() {
    return type.jceName;
  }

  @Override
  public String getFormat() {
    return isPublicKey ? "X.509" : "PKCS#8";
  }

  @Override
  public byte[] getEncoded() {
    final byte[] internalCopy = internalGetEncoded();
    return internalCopy != null ? internalCopy.clone() : null;
  }

  protected byte[] internalGetEncoded() {
    assertNotDestroyed();
    byte[] result = encoded;
    if (result == null) {
      synchronized (this) {
        result = encoded;
        if (result == null) {
          result = isPublicKey ? use(EvpKey::encodePublicKey) : use(EvpKey::encodePrivateKey);
          encoded = result;
        }
      }
    }
    return result;
  }

  protected <X extends Throwable> BigInteger nativeBN(
      final MiscInterfaces.ThrowingLongFunction<byte[], X> fn) throws X {
    byte[] raw = use(fn::apply);
    return new BigInteger(1, raw);
  }

  protected <T extends AlgorithmParameterSpec> T nativeParams(final Class<T> paramSpec) {
    byte[] encodedParams = use(EvpKey::getDerEncodedParams);
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance(type.jceName);
      params.init(encodedParams);
      return params.getParameterSpec(paramSpec);
    } catch (final GeneralSecurityException | IOException ex) {
      throw new RuntimeCryptoException(
          "Unable to deserialize parameters: " + Base64.getEncoder().encodeToString(encodedParams),
          ex);
    }
  }

  /**
   * This method will be called by @{link #destroy()} after possibly calling @{code
   * internalKey.release()}.
   */
  protected synchronized void destroyJavaState() {
    if (encoded != null) {
      Arrays.fill(encoded, (byte) 0);
    }
    encoded = null;
  }

  @Override
  public boolean equals(final Object obj) {
    // We try to avoid comparing the encoded values
    // because it may be slow and may pull secret data into the Java heap
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof Key)) { // Implicit null check
      return false;
    }
    final Key other = (Key) obj;
    if (!getAlgorithm().equalsIgnoreCase(other.getAlgorithm())) {
      return false;
    }

    final byte[] otherEncoded;
    if (obj.getClass().equals(getClass())) {
      // If it is also an EvpKey then we can see if the internal key is the same
      EvpKey evpOther = (EvpKey) obj;
      if (internalKey.equals(evpOther.internalKey)) {
        return true;
      }
      // If it is also an EvpKey then we can grab the other encoded value without copying it
      otherEncoded = evpOther.internalGetEncoded();
    } else {
      otherEncoded = other.getEncoded();
    }

    // Constant time equality check
    return ConstantTime.equals(internalGetEncoded(), otherEncoded);
  }

  @Override
  public int hashCode() {
    // TODO: Consider ways to avoid exposing the entire encoded object to Java for private keys just
    // for a hashCode
    Integer result = cachedHashCode;
    if (result == null) {
      synchronized (this) {
        result = cachedHashCode;
        if (result != null) {
          return cachedHashCode;
        }
        final byte[] internalEncoded = internalGetEncoded();
        // Selected to match implementations of sun.security.pkcs.PKCS8Key and
        // sun.security.x509.X509Key
        int workingValue = 0;
        if (isPublicKey) {
          workingValue = internalEncoded.length;
          for (final byte b : internalEncoded) {
            workingValue += (b & 0xff) * 37;
          }
        } else {
          if (Utils.getJavaVersion() >= 17) {
            workingValue = Arrays.hashCode(internalEncoded);
          } else {
            for (int idx = 0; idx < internalEncoded.length; idx++) {
              workingValue += internalEncoded[idx] * idx;
            }
          }
        }
        result = workingValue;
        cachedHashCode = result;
      }
    }
    return result;
  }

  protected void assertNotDestroyed() {
    if (isDestroyed) {
      throw new IllegalStateException("Key has been destroyed");
    }
  }

  @Override
  public boolean isDestroyed() {
    return isDestroyed;
  }

  @Override
  public synchronized void destroy() {
    assertNotDestroyed();
    isDestroyed = true;
    if (!sharedKey) {
      internalKey.release();
    }
    destroyJavaState();
  }

  protected static class InternalKey extends NativeResource {
    InternalKey(final long ptr) {
      super(ptr, EvpKey::releaseKey, true);
    }
  }

  protected interface CanDerivePublicKey<T extends EvpKey & PublicKey> {
    T getPublicKey();
  }

  /*
   * Java Keys are Serializable but we cannot use the trivial serialization of an EvpKey.
   * - They contain a pointer to native memory (and associated native memory).
   *   This obviously cannot remain valid after being serialized/deserialized.
   * - The pointer to native memory is final to ensure there is no risk of it being invalid.
   *   This means that we cannot just fix it up when deserializing.
   *
   * The trivial solution would be to make the pointer non-final, but that introduces a greater risk of serious bugs.
   *
   * Instead, we use writeReplace() and readResolve() to store our information in a dedicated format for serialization.
   * - writeReplace() on the object to be serialized (an EvpKey) returns the *real* object to be serialized.
   *   In our case, we return an instance of SerializedKey which contains the minimal information to properly save and retrieve a key.
   * - readResolve() is called on the object which is *actually* serialized (and thus being deserialized) and returns the object that users care about.
   *   In our case, SeralizedKey.readResolve() returns an appropriate instance of EvpKey.
   *
   * So, the entire (hidden from the user) flow goes like this.
   * 1.  User tries to serialize an EvpKey
   * 2.  Java detects that EvpKey.writeReplace() exists and calls it
   * 3.  EvpKey.writeReplace() returns an instance of SerializedKey
   * 4.  Java actually serializes SerializedKey
   * 5.  (Some time passes)
   * 6.  User tries to deserialize the bytes
   * 7.  Java detects that the bytes contain a serialized SerializedKey and so deserializes it.
   * 8.  Java detects that SerializedKey.readResolve() exists and calls it
   * 9.  SerializedKey.readResolve() creates and returns an instance of EvpKey
   * 10. User gets an instance of EvpKey and never realizes that the above complexity exists
   */
  Object writeReplace() throws ObjectStreamException {
    return new SerializedKey(type, isPublicKey, internalGetEncoded());
  }

  // This object must never be serialized directly
  private void writeObject(final ObjectOutputStream out) throws IOException {
    throw new NotSerializableException("EvpKey");
  }

  // This object must never be deserialized directly
  private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    throw new NotSerializableException("EvpKey");
  }

  // This object must never be deserialized directly
  private void readObjectNoData() throws ObjectStreamException {
    throw new NotSerializableException("EvpKey");
  }

  /**
   * Minimal information needed to serialize/deserialize any instance of EvpKey. Contains the key
   * type, whether it is a public key, and the appropriate encoding of it.
   */
  private static class SerializedKey implements Serializable {
    private static final long serialVersionUID = 1;
    private final EvpKeyType type;
    private final boolean isPublicKey;
    private final byte[] encoded;

    public SerializedKey(final EvpKeyType type, final boolean isPublicKey, final byte[] encoded) {
      this.type = type;
      this.isPublicKey = isPublicKey;
      this.encoded = encoded;
    }

    private Object readResolve() throws ObjectStreamException {
      try {
        final KeyFactory kf = AmazonCorrettoCryptoProvider.INSTANCE.getKeyFactory(type);
        if (isPublicKey) {
          return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } else {
          return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        }
      } catch (final InvalidKeySpecException ex) {
        throw new InvalidObjectException(ex.getMessage());
      }
    }
  }
}
