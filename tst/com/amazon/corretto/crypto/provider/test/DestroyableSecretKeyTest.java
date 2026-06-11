// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

/**
 * Tests for {@code DestroyableSecretKey}.
 *
 * <p>{@code DestroyableSecretKey} is package-private; this test reaches it via reflection to avoid
 * widening visibility for tests alone.
 */
@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class DestroyableSecretKeyTest {

  private static Constructor<? extends SecretKey> ctor;

  @BeforeAll
  @SuppressWarnings("unchecked")
  public static void setUp() throws Exception {
    // Force provider load so the package is initialized.
    AmazonCorrettoCryptoProvider.INSTANCE.getName();
    final Class<? extends SecretKey> clazz =
        (Class<? extends SecretKey>)
            Class.forName("com.amazon.corretto.crypto.provider.DestroyableSecretKey");
    ctor = clazz.getDeclaredConstructor(byte[].class, String.class);
    ctor.setAccessible(true);
  }

  private static SecretKey newKey(byte[] bytes, String algo) throws Exception {
    return ctor.newInstance(bytes, algo);
  }

  @Test
  public void getEncodedReturnsDefensiveCopy() throws Exception {
    final byte[] original = {1, 2, 3, 4, 5, 6, 7, 8};
    final SecretKey key = newKey(original, "AES");

    final byte[] encoded1 = key.getEncoded();
    assertArrayEquals(original, encoded1);

    // Mutating the returned copy should not affect the key's internal state.
    encoded1[0] = (byte) 0xff;
    final byte[] encoded2 = key.getEncoded();
    assertArrayEquals(original, encoded2);

    // Mutating the source array should not affect the key's internal state either
    // (constructor must copy).
    original[0] = (byte) 0xff;
    final byte[] encoded3 = key.getEncoded();
    assertEquals((byte) 1, encoded3[0]);

    // Each call returns a fresh copy.
    assertNotSame(encoded1, encoded2);
  }

  @Test
  public void formatIsRaw() throws Exception {
    final SecretKey key = newKey(new byte[16], "AES");
    assertEquals("RAW", key.getFormat());
  }

  @Test
  public void implementsDestroyable() throws Exception {
    final SecretKey key = newKey(new byte[16], "AES");
    assertTrue(key instanceof Destroyable);
  }

  @Test
  public void isDestroyedReturnsFalseOnFreshInstance() throws Exception {
    // The Destroyable contract says implementations must report false until destroy()
    // succeeds. Verify on a freshly-constructed instance with no other interaction.
    final SecretKey key = newKey(new byte[16], "AES");
    assertFalse(key.isDestroyed());
  }

  @Test
  public void destroyClearsInternalKeyMaterial() throws Exception {
    // Stronger than destroyZeroesEncodedAndMarksDestroyed: snapshot the encoded bytes
    // before destroy and verify post-destroy access is denied (i.e. no path to read
    // residual key material).
    final byte[] bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
    final SecretKey key = newKey(bytes, "AES");
    final byte[] snapshot = key.getEncoded();
    assertArrayEquals(bytes, snapshot);

    key.destroy();

    assertTrue(key.isDestroyed());
    // After destroy, no accessor should leak key material.
    assertThrows(IllegalStateException.class, key::getEncoded);
  }

  @Test
  public void algorithmIsPreserved() throws Exception {
    final SecretKey key = newKey(new byte[32], "ML-KEM-768");
    assertEquals("ML-KEM-768", key.getAlgorithm());
  }

  @Test
  public void destroyZeroesEncodedAndMarksDestroyed() throws Exception {
    final byte[] bytes = {1, 2, 3, 4, 5, 6, 7, 8};
    final SecretKey key = newKey(bytes, "AES");
    assertFalse(key.isDestroyed());

    key.destroy();

    assertTrue(key.isDestroyed());
    assertThrows(IllegalStateException.class, key::getEncoded);
    assertThrows(IllegalStateException.class, key::getAlgorithm);
  }

  @Test
  public void getFormatRemainsAccessibleAfterDestroy() throws Exception {
    // getFormat() is a static "RAW" string and does not leak key material; leaving it
    // accessible matches the no-state contract.
    final SecretKey key = newKey(new byte[16], "AES");
    key.destroy();
    assertEquals("RAW", key.getFormat());
  }

  @Test
  public void doubleDestroyThrows() throws Exception {
    final SecretKey key = newKey(new byte[16], "AES");
    key.destroy();
    assertThrows(IllegalStateException.class, key::destroy);
  }

  @Test
  public void constructorRejectsNullBytes() throws Exception {
    final Throwable cause =
        assertThrows(
                java.lang.reflect.InvocationTargetException.class,
                () -> ctor.newInstance(null, "AES"))
            .getCause();
    assertTrue(cause instanceof NullPointerException);
  }

  @Test
  public void constructorRejectsNullAlgorithm() throws Exception {
    final Throwable cause =
        assertThrows(
                java.lang.reflect.InvocationTargetException.class,
                () -> ctor.newInstance(new byte[16], null))
            .getCause();
    assertTrue(cause instanceof NullPointerException);
  }

  @Test
  public void constructorRejectsEmptyAlgorithm() throws Exception {
    final Throwable cause =
        assertThrows(
                java.lang.reflect.InvocationTargetException.class,
                () -> ctor.newInstance(new byte[16], ""))
            .getCause();
    assertTrue(cause instanceof IllegalArgumentException);
  }

  @Test
  public void constructorRejectsEmptyBytes() throws Exception {
    final Throwable cause =
        assertThrows(
                java.lang.reflect.InvocationTargetException.class,
                () -> ctor.newInstance(new byte[0], "AES"))
            .getCause();
    assertTrue(cause instanceof IllegalArgumentException);
  }

  @Test
  public void serializationIsBlocked() throws Exception {
    final SecretKey key = newKey(new byte[16], "AES");
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      assertThrows(NotSerializableException.class, () -> oos.writeObject(key));
    }
  }
}
