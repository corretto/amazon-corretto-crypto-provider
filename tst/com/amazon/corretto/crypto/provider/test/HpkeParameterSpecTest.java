// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.HpkeKey;
import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Conversion-core tests run on every JDK; real HPKEParameterSpec tests require JDK 26+. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeParameterSpecTest {
  private static final HpkeParameterSpec SUITE =
      HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM;
  private static final String JDK_SPEC_CLASS = "javax.crypto.spec.HPKEParameterSpec";
  private static final byte[] EMPTY = new byte[0];

  @Test
  public void codepoints() {
    assertEquals(0x0041, HpkeParameterSpec.KEM_ML_KEM_768);
    assertEquals(0x0042, HpkeParameterSpec.KEM_ML_KEM_1024);
    assertEquals(0x0001, HpkeParameterSpec.KDF_HKDF_SHA256);
    assertEquals(0x0002, HpkeParameterSpec.KDF_HKDF_SHA384);
    assertEquals(0x0001, HpkeParameterSpec.AEAD_AES_128_GCM);
    assertEquals(0x0002, HpkeParameterSpec.AEAD_AES_256_GCM);
  }

  @Test
  public void namedSuiteConstants() {
    assertSuite(HpkeParameterSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM, 0x0041, 0x0001, 0x0001);
    assertSuite(HpkeParameterSpec.ML_KEM_1024_HKDF_SHA384_AES_256_GCM, 0x0042, 0x0002, 0x0002);
  }

  private static void assertSuite(
      final HpkeParameterSpec spec, final int kem, final int kdf, final int aead) {
    assertEquals(kem, spec.kem_id());
    assertEquals(kdf, spec.kdf_id());
    assertEquals(aead, spec.aead_id());
    assertArrayEquals(new byte[0], spec.info());
    assertNull(spec.encapsulation());
    assertEquals(HpkeParameterSpec.of(kem, kdf, aead), spec);
  }

  @Test
  public void ofSetsIdsAndDefaults() {
    final HpkeParameterSpec spec = HpkeParameterSpec.of(0x0041, 0x0001, 0x0001);
    assertEquals(0x0041, spec.kem_id());
    assertEquals(0x0001, spec.kdf_id());
    assertEquals(0x0001, spec.aead_id());
    assertArrayEquals(new byte[0], spec.info());
    assertNull(spec.encapsulation());
  }

  @Test
  public void ofAcceptsAnyIdInRangeButRejectsOutOfRange() {
    HpkeParameterSpec.of(0, 0, 0);
    HpkeParameterSpec.of(0xFFFF, 0xFFFF, 0xFFFF);
    for (final int invalid : new int[] {-1, 0x10000}) {
      assertEquals(
          "kem_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class,
                  () -> HpkeParameterSpec.of(invalid, invalid, invalid))
              .getMessage());
      assertEquals(
          "kdf_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class,
                  () -> HpkeParameterSpec.of(0x41, invalid, invalid))
              .getMessage());
      assertEquals(
          "aead_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class, () -> HpkeParameterSpec.of(0x41, 1, invalid))
              .getMessage());
    }
  }

  @Test
  public void withersRejectNull() {
    assertEquals(
        "info must not be null",
        Assertions.assertThrows(NullPointerException.class, () -> SUITE.withInfo(null))
            .getMessage());
    assertEquals(
        "encapsulation must not be null",
        Assertions.assertThrows(NullPointerException.class, () -> SUITE.withEncapsulation(null))
            .getMessage());
  }

  @Test
  public void withInfoRejectsEmpty() {
    assertEquals(
        "info is empty",
        Assertions.assertThrows(IllegalArgumentException.class, () -> SUITE.withInfo(new byte[0]))
            .getMessage());
  }

  @Test
  public void withersAreImmutableAndCopyDefensively() {
    final byte[] info = {1, 2, 3};
    final byte[] enc = {4, 5, 6};
    final HpkeParameterSpec withInfo = SUITE.withInfo(info);
    final HpkeParameterSpec withBoth = withInfo.withEncapsulation(enc);

    // The original specs are unchanged.
    assertArrayEquals(new byte[0], SUITE.info());
    assertNull(SUITE.encapsulation());
    assertNull(withInfo.encapsulation());

    // Mutating the inputs does not affect the spec.
    info[0] = 9;
    enc[0] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, withBoth.info());
    assertArrayEquals(new byte[] {4, 5, 6}, withBoth.encapsulation());

    // Mutating the outputs does not affect the spec.
    withBoth.info()[0] = 9;
    withBoth.encapsulation()[0] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, withBoth.info());
    assertArrayEquals(new byte[] {4, 5, 6}, withBoth.encapsulation());
    assertNotSame(withBoth.info(), withBoth.info());

    assertEquals(SUITE.kem_id(), withBoth.kem_id());
    assertEquals(SUITE.kdf_id(), withBoth.kdf_id());
    assertEquals(SUITE.aead_id(), withBoth.aead_id());

    assertEquals(withBoth, SUITE.withEncapsulation(new byte[] {4, 5, 6}).withInfo(withBoth.info()));
  }

  @Test
  public void equalsAndHashCode() {
    final HpkeParameterSpec a = SUITE.withInfo(new byte[] {1}).withEncapsulation(new byte[2]);
    final HpkeParameterSpec b =
        HpkeParameterSpec.of(0x0041, 0x0001, 0x0001)
            .withInfo(new byte[] {1})
            .withEncapsulation(new byte[2]);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(a, SUITE);
    assertNotEquals(a, a.withInfo(new byte[] {2}));
    assertNotEquals(a, a.withEncapsulation(new byte[3]));
    assertNotEquals(SUITE, HpkeParameterSpec.of(0x0041, 0x0002, 0x0001));
    assertNotEquals(SUITE, SUITE.withEncapsulation(new byte[0]));
  }

  private static HpkeParameterSpec fromComponents(
      final int kem,
      final int kdf,
      final int aead,
      final byte[] info,
      final byte[] enc,
      final Object psk,
      final byte[] pskId,
      final Object authKey)
      throws Throwable {
    return sneakyInvoke(
        HpkeParameterSpec.class, "fromComponents", kem, kdf, aead, info, enc, psk, pskId, authKey);
  }

  private static HpkeParameterSpec from(final AlgorithmParameterSpec params) throws Throwable {
    return sneakyInvoke(HpkeParameterSpec.class, "from", params);
  }

  private static void assertRejected(final String message, final ThrowingSupplier call) {
    final InvalidAlgorithmParameterException ex =
        Assertions.assertThrows(InvalidAlgorithmParameterException.class, call::get);
    assertTrue(ex.getMessage().contains(message), ex.getMessage());
  }

  private interface ThrowingSupplier {
    Object get() throws Throwable;
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void convertsCuratedSuites(final HpkeTestSuite suite) throws Throwable {
    final byte[] info = {1, 2, 3};
    final byte[] enc = {4, 5, 6, 7};
    final HpkeParameterSpec spec =
        fromComponents(suite.kemId, suite.kdfId, suite.aeadId, info, enc, null, EMPTY, null);
    assertEquals(suite.spec().withInfo(info).withEncapsulation(enc), spec);
    // Arrays are copied on the way in.
    info[0] = 9;
    enc[0] = 9;
    assertEquals(1, spec.info()[0]);
    assertEquals(4, spec.encapsulation()[0]);
  }

  @Test
  public void emptyInfoAndNoEncapsulation() throws Throwable {
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    final HpkeParameterSpec spec =
        fromComponents(suite.kemId, suite.kdfId, suite.aeadId, EMPTY, null, null, EMPTY, null);
    assertEquals(suite.namedSpec(), spec);
    assertArrayEquals(EMPTY, spec.info());
    assertNull(spec.encapsulation());
    assertEquals(
        suite.namedSpec(),
        fromComponents(suite.kemId, suite.kdfId, suite.aeadId, null, null, null, null, null));
  }

  @Test
  public void rejectsPskAndAuthModes() throws Throwable {
    final HpkeTestSuite s = HpkeTestSuite.MLKEM768;
    final Object psk = new SecretKeySpec(new byte[32], "Generic");
    assertRejected(
        "PSK",
        () -> fromComponents(s.kemId, s.kdfId, s.aeadId, EMPTY, null, psk, new byte[] {1}, null));
    assertRejected(
        "PSK", () -> fromComponents(s.kemId, s.kdfId, s.aeadId, EMPTY, null, psk, EMPTY, null));
    assertRejected(
        "PSK",
        () -> fromComponents(s.kemId, s.kdfId, s.aeadId, EMPTY, null, null, new byte[] {1}, null));
    final Object authKey = new Object();
    assertRejected(
        "auth",
        () -> fromComponents(s.kemId, s.kdfId, s.aeadId, EMPTY, null, null, EMPTY, authKey));
  }

  @Test
  public void fromComponentsLeavesSuiteChecksToInit() throws Throwable {
    // Adaptation preserves unsupported suite ids for validation after the mode check.
    final int[][] suites = {
      {0x0020, 0x0001, 0x0001}, // DHKEM, one of the JDK's classical suites
      {0x0010, 0x0001, 0x0001}, // DHKEM(P-256)
      {0x0041, 0x0001, 0x0003}, // ChaCha20-Poly1305
      {0x0041, 0x0001, 0x0002}, // ML-KEM-768 with a non-curated AEAD
      {0x0042, 0x0001, 0x0001}, // ML-KEM-1024 with a non-curated KDF/AEAD
      {0x0041, 0x0003, 0x0001}, // unknown KDF
      {0x0043, 0x0001, 0x0001}, // unknown KEM
      {0xFFFF, 0xFFFF, 0xFFFF},
    };
    for (final int[] ids : suites) {
      final HpkeParameterSpec spec =
          fromComponents(ids[0], ids[1], ids[2], EMPTY, null, null, EMPTY, null);
      assertEquals(HpkeParameterSpec.of(ids[0], ids[1], ids[2]), spec);
    }
  }

  @Test
  public void adapterSpecForUncuratedSuiteIsRejectedAtInit() throws Throwable {
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    suite.assumeAvailable();
    final HpkeParameterSpec spec = fromComponents(0x0040, 1, 1, EMPTY, null, null, EMPTY, null);
    final KeyPair pair = suite.generateKeyPair();
    final Cipher cipher = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic(), spec));
  }

  @Test
  public void jdkSpecAdapterRejectsUnknownMethods() throws Throwable {
    // The instance methods of JDK 26's HPKEParameterSpec, plus java.lang.Object's.
    final List<String> known =
        new ArrayList<>(
            Arrays.asList(
                "withInfo",
                "withPsk",
                "withEncapsulation",
                "withAuthKey",
                "kem_id",
                "kdf_id",
                "aead_id",
                "info",
                "psk",
                "psk_id",
                "authKey",
                "encapsulation",
                "toString",
                "hashCode",
                "equals",
                "getClass",
                "notify",
                "notifyAll",
                "wait"));
    assertTrue(onlyKnownJdkSpecMethods(known));
    assertTrue(onlyKnownJdkSpecMethods(new ArrayList<String>()));
    // A new public method may mean a new field that the adapter would silently drop.
    known.add("withExportOnly");
    assertFalse(onlyKnownJdkSpecMethods(known));
  }

  private static boolean onlyKnownJdkSpecMethods(final List<String> names) throws Throwable {
    final List<String> unknown =
        TestUtil.sneakyInvoke(HpkeParameterSpec.class, "unknownJdkSpecMethods", (Object) names);
    return unknown.isEmpty();
  }

  @Test
  public void unadaptableJdkSpecSaysWhy() throws Throwable {
    final List<String> names = new ArrayList<>(Arrays.asList("kem_id", "zeta", "info", "alpha"));
    final List<String> unknown =
        TestUtil.sneakyInvoke(HpkeParameterSpec.class, "unknownJdkSpecMethods", (Object) names);
    assertEquals(Arrays.asList("alpha", "zeta"), unknown);
    final String message =
        TestUtil.sneakyInvoke(
            HpkeParameterSpec.class, "unadaptableJdkSpecMessage", (Object) unknown);
    assertEquals(
        "ACCP does not recognize method(s) [alpha, zeta] of "
            + JDK_SPEC_CLASS
            + " on this JDK;"
            + " use com.amazon.corretto.crypto.provider.HpkeParameterSpec or upgrade ACCP",
        message);
    final String unreadable =
        TestUtil.sneakyInvoke(HpkeParameterSpec.class, "unadaptableJdkSpecMessage", (Object) null);
    assertTrue(unreadable.startsWith("ACCP cannot read " + JDK_SPEC_CLASS), unreadable);
    assertTrue(unreadable.endsWith("or upgrade ACCP"), unreadable);
  }

  @Test
  public void fromPassesAccpSpecsThrough() throws Throwable {
    final HpkeParameterSpec spec =
        HpkeTestSuite.MLKEM768.spec().withInfo(new byte[] {1}).withEncapsulation(new byte[] {2});
    assertSame(spec, from(spec));
  }

  @Test
  public void fromRejectsNullAndForeignSpecs() {
    assertRejected(
        "An HpkeParameterSpec (or, on JDK 26+, javax.crypto.spec.HPKEParameterSpec) must be"
            + " provided",
        () -> from(null));
    assertRejected(
        "Unsupported params type: " + ECGenParameterSpec.class.getName(),
        () -> from(new ECGenParameterSpec("secp256r1")));
  }

  private static Class<?> jdkSpecClassOrSkip() {
    Class<?> cls = null;
    try {
      cls = Class.forName(JDK_SPEC_CLASS);
    } catch (final ClassNotFoundException ex) {
      // Not on this JDK.
    }
    assumeTrue(cls != null, JDK_SPEC_CLASS + " requires JDK 26+");
    return cls;
  }

  /** {@code HPKEParameterSpec.of(kem, kdf, aead)}, optionally {@code .withInfo(info)}. */
  private static AlgorithmParameterSpec jdkSpec(
      final Class<?> cls, final HpkeTestSuite suite, final byte[] info) throws Exception {
    Object spec =
        cls.getMethod("of", int.class, int.class, int.class)
            .invoke(null, suite.kemId, suite.kdfId, suite.aeadId);
    if (info != null) {
      spec = cls.getMethod("withInfo", byte[].class).invoke(spec, (Object) info);
    }
    return (AlgorithmParameterSpec) spec;
  }

  private static AlgorithmParameterSpec withEncapsulation(
      final Class<?> cls, final AlgorithmParameterSpec spec, final byte[] enc) throws Exception {
    return (AlgorithmParameterSpec)
        cls.getMethod("withEncapsulation", byte[].class).invoke(spec, (Object) enc);
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void realJdkSpecRoundTrip(final HpkeTestSuite suite) throws Exception {
    final Class<?> cls = jdkSpecClassOrSkip();
    suite.assumeAvailable();
    final byte[] info = {1, 2, 3};
    final byte[] aad = {4, 5};
    final byte[] plaintext = {6, 7, 8, 9};

    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER);
    kpg.initialize(jdkSpec(cls, suite, null));
    final KeyPair pair = kpg.generateKeyPair();
    assertEquals(suite.namedSpec(), ((HpkeKey) pair.getPublic()).parameterSpec());

    final AlgorithmParameterSpec spec = jdkSpec(cls, suite, info);
    final Cipher sender = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    sender.init(Cipher.ENCRYPT_MODE, pair.getPublic(), spec);
    final byte[] enc = sender.getIV();
    assertEquals(suite.encLength, enc.length);
    sender.updateAAD(aad);
    final byte[] ct = sender.doFinal(plaintext);

    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(
        Cipher.DECRYPT_MODE, pair.getPrivate(), withEncapsulation(cls, spec, enc.clone()));
    recipient.updateAAD(aad);
    assertArrayEquals(plaintext, recipient.doFinal(ct));

    final Cipher accpRecipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    accpRecipient.init(
        Cipher.DECRYPT_MODE,
        pair.getPrivate(),
        suite.spec().withInfo(info).withEncapsulation(Arrays.copyOf(enc, enc.length)));
    accpRecipient.updateAAD(aad);
    assertArrayEquals(plaintext, accpRecipient.doFinal(ct));
  }

  @Test
  public void realJdkSpecRejectedModesAndSuites() throws Exception {
    final Class<?> cls = jdkSpecClassOrSkip();
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    suite.assumeAvailable();
    final KeyPair pair = suite.generateKeyPair();
    final Cipher cipher = Cipher.getInstance("HPKE", NATIVE_PROVIDER);

    final Object dhkem =
        cls.getMethod("of", int.class, int.class, int.class).invoke(null, 0x0020, 1, 1);
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic(), (AlgorithmParameterSpec) dhkem));
    for (final Key key : new Key[] {pair.getPublic(), pair.getPrivate()}) {
      Assertions.assertThrows(
          UnsupportedOperationException.class,
          () -> cipher.init(Cipher.WRAP_MODE, key, (AlgorithmParameterSpec) dhkem));
      Assertions.assertThrows(
          UnsupportedOperationException.class,
          () -> cipher.init(Cipher.UNWRAP_MODE, key, (AlgorithmParameterSpec) dhkem));
    }
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER);
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kpg.initialize((AlgorithmParameterSpec) dhkem));
    final Object uncurated =
        cls.getMethod("of", int.class, int.class, int.class).invoke(null, 0x0040, 1, 1);
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic(), (AlgorithmParameterSpec) uncurated));
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> kpg.initialize((AlgorithmParameterSpec) uncurated));

    final Object psk =
        cls.getMethod("withPsk", SecretKey.class, byte[].class)
            .invoke(
                jdkSpec(cls, suite, null),
                new SecretKeySpec(new byte[32], "Generic"),
                new byte[] {1});
    Assertions.assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic(), (AlgorithmParameterSpec) psk));
  }
}
