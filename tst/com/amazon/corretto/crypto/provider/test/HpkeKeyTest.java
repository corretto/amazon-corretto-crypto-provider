// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.HpkeKey;
import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.Destroyable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeKeyTest {
  private static final byte[] PLAINTEXT = "hello".getBytes(StandardCharsets.UTF_8);

  private static void assumeHpkeRegistered() {
    assumeTrue(HpkeTestSuite.anyAvailable(), "the linked AWS-LC provides no HPKE suite");
  }

  private static KeyPairGenerator generator() throws Exception {
    assumeHpkeRegistered();
    return KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER);
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void generate(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    for (final Key key : new Key[] {kp.getPublic(), kp.getPrivate()}) {
      assertEquals("HPKE", key.getAlgorithm());
      assertEquals("RAW", key.getFormat());
    }
    assertTrue(kp.getPrivate() instanceof Destroyable);
    final KeyPair other = suite.generateKeyPair();
    assertNotEquals(kp.getPublic(), other.getPublic());
    assertNotEquals(kp.getPrivate(), other.getPrivate());
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void publicEncodingLengths(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    assertEquals(suite.publicKeyLength, suite.generateKeyPair().getPublic().getEncoded().length);
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void privateEncodingLengths(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    // Independent seed-length expectation; see HpkeKey's encoding contract.
    assertEquals(suite.seedLength, suite.generateKeyPair().getPrivate().getEncoded().length);
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void encodedRoundTrip(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final byte[] rawPub = kp.getPublic().getEncoded();
    final PublicKey pub = HpkePublicKey.fromEncoded(suite.namedSpec(), rawPub);
    final PrivateKey priv =
        HpkePrivateKey.fromEncoded(suite.namedSpec(), kp.getPrivate().getEncoded());
    assertEquals(kp.getPublic(), pub);
    assertEquals(kp.getPrivate(), priv);
    assertEquals(kp.getPublic().hashCode(), pub.hashCode());
    assertEquals(kp.getPrivate().hashCode(), priv.hashCode());
    assertArrayEquals(rawPub, pub.getEncoded());
    assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded());
    assertEquals(pub, HpkePublicKey.fromEncoded(suite.spec().withInfo(PLAINTEXT), rawPub));
    assertEquals(pub, HpkePublicKey.fromEncoded(suite.spec(), rawPub));
    // Import and export must both copy defensively.
    final byte[] input = rawPub.clone();
    final PublicKey copy = HpkePublicKey.fromEncoded(suite.namedSpec(), input);
    input[0] ^= 1;
    copy.getEncoded()[1] ^= 1;
    assertArrayEquals(rawPub, copy.getEncoded());
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void seedImportIsDeterministic(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final byte[] seed = new byte[suite.seedLength];
    Arrays.fill(seed, (byte) 0x42);
    final PrivateKey a = HpkePrivateKey.fromEncoded(suite.namedSpec(), seed);
    final PrivateKey b = HpkePrivateKey.fromEncoded(suite.namedSpec(), seed);
    assertEquals(a, b);
    assertArrayEquals(seed, a.getEncoded());
    // The caller's seed is neither modified nor kept.
    final byte[] expected = new byte[suite.seedLength];
    Arrays.fill(expected, (byte) 0x42);
    assertArrayEquals(expected, seed);
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void fromEncodedRejectsWrongLengths(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    for (final int delta : new int[] {-1, 1}) {
      assertThrows(
          InvalidKeyException.class,
          () ->
              HpkePublicKey.fromEncoded(
                  suite.namedSpec(), new byte[suite.publicKeyLength + delta]));
      assertThrows(
          InvalidKeyException.class,
          () -> HpkePrivateKey.fromEncoded(suite.namedSpec(), new byte[suite.seedLength + delta]));
    }
    assertThrows(
        InvalidKeyException.class,
        () -> HpkePrivateKey.fromEncoded(suite.namedSpec(), new byte[0]));
  }

  @Test
  public void fromEncodedRejectsMlKemExpandedPrivateKey() throws Exception {
    HpkeTestSuite.MLKEM768.assumeAvailable();
    // The ML-KEM-768 expanded decapsulation key is 2400 bytes; only the 64-byte seed is accepted.
    assertThrows(
        InvalidKeyException.class,
        () ->
            HpkePrivateKey.fromEncoded(
                HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM, new byte[2400]));
  }

  @Test
  public void fromEncodedRejectsUncuratedSuitesAndNulls() throws Exception {
    assumeHpkeRegistered();
    // 0x0010 is the RFC 9180 P-256 KEM, which ACCP's HPKE does not offer.
    final HpkeParameterSpec p256 = HpkeParameterSpec.of(0x0010, 0x0001, 0x0001);
    assertThrows(InvalidKeyException.class, () -> HpkePublicKey.fromEncoded(p256, new byte[65]));
    assertThrows(InvalidKeyException.class, () -> HpkePrivateKey.fromEncoded(p256, new byte[32]));
    // A curated KEM with another KDF and AEAD.
    final HpkeParameterSpec other = HpkeParameterSpec.of(0x0041, 0x0002, 0x0002);
    assertThrows(
        InvalidKeyException.class,
        () -> HpkePublicKey.fromEncoded(other, new byte[HpkeTestSuite.MLKEM768.publicKeyLength]));
    assertThrows(
        InvalidKeyException.class,
        () -> HpkePrivateKey.fromEncoded(other, new byte[HpkeTestSuite.MLKEM768.seedLength]));
    final HpkeParameterSpec named = HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM;
    assertThrows(
        IllegalArgumentException.class, () -> HpkePublicKey.fromEncoded(null, new byte[1]));
    assertThrows(
        IllegalArgumentException.class, () -> HpkePrivateKey.fromEncoded(null, new byte[1]));
    assertThrows(IllegalArgumentException.class, () -> HpkePublicKey.fromEncoded(named, null));
    assertThrows(IllegalArgumentException.class, () -> HpkePrivateKey.fromEncoded(named, null));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void keysAreBoundToTheirSuite(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Key[] keys = {
      kp.getPublic(),
      kp.getPrivate(),
      HpkePublicKey.fromEncoded(suite.namedSpec(), kp.getPublic().getEncoded()),
      HpkePrivateKey.fromEncoded(suite.namedSpec(), kp.getPrivate().getEncoded()),
      ((HpkePrivateKey) kp.getPrivate()).getPublicKey(),
    };
    for (final Key key : keys) {
      final HpkeKey hpkeKey = (HpkeKey) key;
      assertEquals(suite.encLength, hpkeKey.encapsulationLength());
      assertSame(suite.namedSpec(), hpkeKey.parameterSpec());
    }
    assertTrue(kp.getPublic() instanceof HpkePublicKey);
    assertEquals(kp.getPublic(), ((HpkePrivateKey) kp.getPrivate()).getPublicKey());
  }

  // ML-KEM public keys are checked at import (FIPS 203 section 7.2 modulus check), so a malformed
  // key fails there with a checked InvalidKeyException and never reaches a Cipher.
  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void allFfPublicKeyRejected(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final byte[] raw = new byte[suite.publicKeyLength];
    Arrays.fill(raw, (byte) 0xFF);
    assertThrows(
        InvalidKeyException.class, () -> HpkePublicKey.fromEncoded(suite.namedSpec(), raw));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void firstCoefficientEqualToQRejected(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final byte[] raw = suite.generateKeyPair().getPublic().getEncoded();
    assertEquals(suite.publicKeyLength, raw.length);
    // Coefficient 0 is the low 12 bits of the first 3 bytes (little-endian).
    raw[0] = 0x01;
    raw[1] = (byte) ((raw[1] & 0xF0) | 0x0D);
    assertEquals(3329, (raw[0] & 0xFF) | ((raw[1] & 0x0F) << 8));
    assertThrows(
        InvalidKeyException.class, () -> HpkePublicKey.fromEncoded(suite.namedSpec(), raw));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void controlGeneratedKeyImportsAndSeals(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final PublicKey pub = HpkePublicKey.fromEncoded(suite.namedSpec(), kp.getPublic().getEncoded());
    final Cipher sender = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    sender.init(Cipher.ENCRYPT_MODE, pub, suite.spec());
    final byte[] ct = sender.doFinal(PLAINTEXT);
    assertEquals(PLAINTEXT.length + HpkeTestSuite.AEAD_OVERHEAD, ct.length);
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(
        Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(sender.getIV()));
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct));
  }

  @Test
  public void generatorBindsTheSpecSuite() throws Exception {
    final KeyPairGenerator kpg = generator();
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      if (!suite.isAvailable()) {
        continue;
      }
      kpg.initialize(suite.spec().withInfo(new byte[] {1}));
      final KeyPair kp = kpg.generateKeyPair();
      for (final Key key : new Key[] {kp.getPublic(), kp.getPrivate()}) {
        assertSame(suite.namedSpec(), ((HpkeKey) key).parameterSpec());
      }
      assertEquals(suite.publicKeyLength, kp.getPublic().getEncoded().length);
    }
  }

  @Test
  public void generatorRejectsUncuratedSuite() throws Exception {
    final KeyPairGenerator kpg = generator();
    for (final HpkeParameterSpec spec :
        new HpkeParameterSpec[] {
          HpkeParameterSpec.of(0x0020, 0x0001, 0x0001),
          HpkeParameterSpec.of(0x0010, 0x0001, 0x0001),
          HpkeParameterSpec.of(0x0041, 0x0002, 0x0002),
          HpkeParameterSpec.of(0x0042, 0x0001, 0x0001),
        }) {
      assertThrows(InvalidAlgorithmParameterException.class, () -> kpg.initialize(spec));
    }
  }

  @Test
  public void generatorRequiresHpkeParameterSpec() throws Exception {
    final KeyPairGenerator kpg = generator();
    assertThrows(IllegalStateException.class, kpg::generateKeyPair);
    assertThrows(UnsupportedOperationException.class, () -> kpg.initialize(256));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kpg.initialize(new IvParameterSpec(new byte[16])));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kpg.initialize((AlgorithmParameterSpec) null));
    assertThrows(IllegalStateException.class, kpg::generateKeyPair);
  }

  @Test
  public void destroy() throws Exception {
    HpkeTestSuite.MLKEM768.assumeAvailable();
    final KeyPair kp = HpkeTestSuite.MLKEM768.generateKeyPair();
    final PrivateKey priv = kp.getPrivate();
    final byte[] pub = kp.getPublic().getEncoded();
    assertFalse(((Destroyable) priv).isDestroyed());
    ((Destroyable) priv).destroy();
    assertTrue(((Destroyable) priv).isDestroyed());
    assertThrows(IllegalStateException.class, priv::getEncoded);
    assertThrows(IllegalStateException.class, () -> ((Destroyable) priv).destroy());
    // The public key is independent of the private key's native handle.
    assertArrayEquals(pub, kp.getPublic().getEncoded());
  }

  @Test
  public void equalsWithADestroyedKey() throws Exception {
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    suite.assumeAvailable();
    final HpkePrivateKey live = (HpkePrivateKey) suite.generateKeyPair().getPrivate();
    final HpkePrivateKey destroyed =
        HpkePrivateKey.fromEncoded(suite.namedSpec(), live.getEncoded());
    destroyed.destroy();
    // Either side being destroyed throws; equals must still wipe the seed copy it already took.
    assertThrows(IllegalStateException.class, () -> live.equals(destroyed));
    assertThrows(IllegalStateException.class, () -> destroyed.equals(live));
    assertEquals(suite.seedLength, live.getEncoded().length);
    assertEquals(live, HpkePrivateKey.fromEncoded(suite.namedSpec(), live.getEncoded()));
  }

  @Test
  public void keysAreNotSerializable() throws Exception {
    HpkeTestSuite.MLKEM768.assumeAvailable();
    final KeyPair kp = HpkeTestSuite.MLKEM768.generateKeyPair();
    for (final Key key : new Key[] {kp.getPublic(), kp.getPrivate()}) {
      try (ObjectOutputStream out = new ObjectOutputStream(new ByteArrayOutputStream())) {
        assertThrows(NotSerializableException.class, () -> out.writeObject(key));
      }
    }
  }
}
