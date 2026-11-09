// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.HpkeTestSuite.cipher;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.HpkeKey;
import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.Destroyable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeCipherTest {
  private static final byte[] INFO = "HPKE test info".getBytes(StandardCharsets.UTF_8);
  private static final byte[] AAD = "HPKE test aad".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PLAINTEXT =
      "Beauty is truth, truth beauty".getBytes(StandardCharsets.UTF_8);

  /** Encrypts with a fresh sender Cipher; returns {enc, ciphertext}. */
  private static byte[][] seal(
      final PublicKey pub, final HpkeParameterSpec spec, final byte[] aad, final byte[] plaintext)
      throws Exception {
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, pub, spec);
    final byte[] enc = sender.getIV();
    if (aad != null) {
      sender.updateAAD(aad);
    }
    final byte[] ct = sender.doFinal(plaintext);
    return new byte[][] {enc, ct};
  }

  /** The first suite the linked AWS-LC provides; skips the test if there is none. */
  private static HpkeTestSuite anyAvailableSuite() {
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      if (suite.isAvailable()) {
        return suite;
      }
    }
    assumeTrue(false, "the linked AWS-LC provides no HPKE suite");
    throw new AssertionError("unreachable");
  }

  private static byte[] open(
      final PrivateKey priv,
      final HpkeParameterSpec spec,
      final byte[] enc,
      final byte[] aad,
      final byte[] ciphertext)
      throws Exception {
    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, priv, spec.withEncapsulation(enc));
    if (aad != null) {
      recipient.updateAAD(aad);
    }
    return recipient.doFinal(ciphertext);
  }

  private static Cipher recipient(final HpkeTestSuite suite, final KeyPair kp, final byte[] enc)
      throws Exception {
    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(enc));
    return recipient;
  }

  private static byte[] message(final int i) {
    return ("message " + i).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] aad(final int i) {
    return ("aad " + i).getBytes(StandardCharsets.UTF_8);
  }

  public static List<Arguments> roundTripParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      for (final boolean withInfo : new boolean[] {false, true}) {
        for (final boolean withAad : new boolean[] {false, true}) {
          result.add(Arguments.of(suite, withInfo, withAad));
        }
      }
    }
    return result;
  }

  @Test
  public void servicesRegisteredIffAnySuiteAvailable() throws Exception {
    final boolean any = HpkeTestSuite.anyAvailable();
    for (final String type : new String[] {"Cipher", "KeyPairGenerator"}) {
      assertEquals(any, NATIVE_PROVIDER.getService(type, "HPKE") != null, type);
    }
    assertNull(NATIVE_PROVIDER.getService("AlgorithmParameters", "HPKE"));
    assertNull(NATIVE_PROVIDER.getService("KeyFactory", "HPKE"));
    if (!any) {
      assertThrows(
          NoSuchAlgorithmException.class, () -> Cipher.getInstance("HPKE", NATIVE_PROVIDER));
    }
  }

  @Test
  public void supportedKeyClassesNamesAccpKeysOnly() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    final Provider.Service service = NATIVE_PROVIDER.getService("Cipher", "HPKE");
    assertNotNull(service);
    // ACCP's ML-KEM keys are listed too, so that they reach HpkeCipher's import advice.
    assertEquals(
        HpkeKey.class.getName() + "|com.amazon.corretto.crypto.provider.EvpKemKey",
        service.getAttribute("SupportedKeyClasses"));
    assertTrue(service.supportsParameter(kp.getPublic()));
    assertTrue(service.supportsParameter(kp.getPrivate()));
    if (NATIVE_PROVIDER.getService("KeyPairGenerator", "ML-KEM-768") != null) {
      final KeyPair mlkem =
          KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
      assertTrue(service.supportsParameter(mlkem.getPublic()));
      assertTrue(service.supportsParameter(mlkem.getPrivate()));
    }
    for (final String algorithm : new String[] {"RSA", "EC"}) {
      final KeyPair foreign =
          KeyPairGenerator.getInstance(algorithm, NATIVE_PROVIDER).generateKeyPair();
      assertFalse(service.supportsParameter(foreign.getPublic()), algorithm);
      assertFalse(service.supportsParameter(foreign.getPrivate()), algorithm);
    }
    assertNull(
        NATIVE_PROVIDER.getService("KeyPairGenerator", "HPKE").getAttribute("SupportedKeyClasses"));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void ivParametersAndBlockSize(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    assertNull(sender.getIV());
    assertNull(sender.getParameters());
    assertEquals(0, sender.getBlockSize());
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] enc = sender.getIV();
    assertEquals(suite.encLength, enc.length);
    assertNull(sender.getParameters());
    assertEquals(16, sender.getBlockSize());
    // getIV returns a copy, stable across doFinal.
    enc[0] ^= 1;
    final byte[] ct = sender.doFinal(PLAINTEXT);
    final byte[] enc2 = sender.getIV();
    enc[0] ^= 1;
    assertArrayEquals(enc, enc2);
    final Cipher recipient = cipher();
    assertEquals(0, recipient.getBlockSize());
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(enc));
    assertNull(recipient.getIV());
    assertNull(recipient.getParameters());
    assertEquals(16, recipient.getBlockSize());
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct));
  }

  @Test
  public void testSuiteAvailabilityMatchesLinkedAwsLc() {
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      final boolean available = suite.isAvailable();
      assertEquals(
          NativeTestHooks.hpkeSuiteAvailable(suite.kemId, suite.kdfId, suite.aeadId),
          available,
          suite + ": ACCP availability differs from the linked AWS-LC capability");
    }
  }

  @ParameterizedTest
  @MethodSource("roundTripParams")
  public void roundTrip(final HpkeTestSuite suite, final boolean withInfo, final boolean withAad)
      throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final HpkeParameterSpec spec = withInfo ? suite.spec().withInfo(INFO) : suite.spec();
    final byte[] aad = withAad ? AAD : null;
    final byte[][] sealed = seal(kp.getPublic(), spec, aad, PLAINTEXT);
    assertEquals(suite.encLength, sealed[0].length);
    assertEquals(PLAINTEXT.length + HpkeTestSuite.AEAD_OVERHEAD, sealed[1].length);
    assertArrayEquals(PLAINTEXT, open(kp.getPrivate(), spec, sealed[0], aad, sealed[1]));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void emptyPlaintext(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] ct = sender.doFinal();
    assertEquals(HpkeTestSuite.AEAD_OVERHEAD, ct.length);
    final byte[] enc = sender.getIV();
    assertArrayEquals(new byte[0], open(kp.getPrivate(), suite.spec(), enc, null, ct));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void largePlaintext(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final byte[] plaintext = new byte[(1 << 20) + 13];
    new Random(42).nextBytes(plaintext);
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec().withInfo(INFO));
    sender.updateAAD(AAD);
    assertEquals(
        plaintext.length + HpkeTestSuite.AEAD_OVERHEAD, sender.getOutputSize(plaintext.length));

    final byte[] enc = sender.getIV();
    // A short-buffer retry must not consume a sequence number.
    final byte[] tooSmall = new byte[plaintext.length + HpkeTestSuite.AEAD_OVERHEAD - 1];
    assertThrows(
        ShortBufferException.class, () -> sender.doFinal(plaintext, 0, plaintext.length, tooSmall));
    assertArrayEquals(enc, sender.getIV());

    final byte[] input = new byte[plaintext.length + 7];
    System.arraycopy(plaintext, 0, input, 3, plaintext.length);
    final byte[] output = new byte[plaintext.length + HpkeTestSuite.AEAD_OVERHEAD + 5];
    final int ctLen = sender.doFinal(input, 3, plaintext.length, output, 5);
    assertEquals(plaintext.length + HpkeTestSuite.AEAD_OVERHEAD, ctLen);
    final byte[] ct = Arrays.copyOfRange(output, 5, 5 + ctLen);

    final Cipher recipient = cipher();
    recipient.init(
        Cipher.DECRYPT_MODE,
        kp.getPrivate(),
        suite.spec().withInfo(INFO).withEncapsulation(sender.getIV()));
    recipient.updateAAD(ByteBuffer.wrap(AAD));
    assertEquals(plaintext.length, recipient.getOutputSize(ct.length));
    final byte[] decrypted = new byte[plaintext.length + 2];
    assertEquals(plaintext.length, recipient.doFinal(ct, 0, ct.length, decrypted, 2));
    assertArrayEquals(plaintext, Arrays.copyOfRange(decrypted, 2, 2 + plaintext.length));
  }

  @Test
  public void aadMayBeSuppliedInPieces() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    sender.updateAAD(AAD, 0, 4);
    sender.updateAAD(ByteBuffer.wrap(AAD, 4, AAD.length - 4));
    final byte[] ct = sender.doFinal(PLAINTEXT);
    assertArrayEquals(PLAINTEXT, open(kp.getPrivate(), suite.spec(), sender.getIV(), AAD, ct));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void importedKeysInteroperate(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final PublicKey importedPub =
        HpkePublicKey.fromEncoded(suite.namedSpec(), kp.getPublic().getEncoded());
    final PrivateKey importedPriv =
        HpkePrivateKey.fromEncoded(suite.namedSpec(), kp.getPrivate().getEncoded());
    final byte[][] sealed = seal(importedPub, suite.spec(), null, PLAINTEXT);
    assertArrayEquals(PLAINTEXT, open(importedPriv, suite.spec(), sealed[0], null, sealed[1]));
  }

  @Test
  public void rejectsUncuratedSuite() throws Exception {
    final KeyPair kp = anyAvailableSuite().generateKeyPair();
    for (final HpkeParameterSpec spec :
        new HpkeParameterSpec[] {
          // Valid RFC 9180 suites with classical KEMs, which ACCP does not offer.
          HpkeParameterSpec.of(0x0020, 0x0001, 0x0001),
          HpkeParameterSpec.of(0x0010, 0x0001, 0x0001),
          // Curated KEMs with another KDF or AEAD.
          HpkeParameterSpec.of(0x0041, 0x0002, 0x0002),
          HpkeParameterSpec.of(0x0042, 0x0001, 0x0001),
          // Export-only AEAD.
          HpkeParameterSpec.of(0x0041, 0x0001, 0xFFFF),
          // An ML-KEM KEM id that ACCP does not curate.
          HpkeParameterSpec.of(0x0040, 0x0001, 0x0001),
        }) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), spec));
    }
    final HpkeParameterSpec uncurated = HpkeParameterSpec.of(0x0040, 0x0001, 0x0001);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER).initialize(uncurated));
    assertThrows(
        InvalidKeyException.class, () -> HpkePublicKey.fromEncoded(uncurated, new byte[800]));
    assertThrows(
        InvalidKeyException.class, () -> HpkePrivateKey.fromEncoded(uncurated, new byte[64]));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void rejectsUnavailableSuite(final HpkeTestSuite suite) throws Exception {
    // Runs only on an AWS-LC that provides some suites but not this one, e.g. ML-KEM without
    // HKDF-SHA384.
    assumeTrue(!suite.isAvailable(), suite + " is available");
    final KeyPair kp = anyAvailableSuite().generateKeyPair();
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec()));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            cipher()
                .init(
                    Cipher.DECRYPT_MODE,
                    kp.getPrivate(),
                    suite.spec().withEncapsulation(new byte[suite.encLength])));
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class, () -> generator.initialize(suite.spec()));
    assertThrows(
        InvalidKeyException.class,
        () -> HpkePublicKey.fromEncoded(suite.spec(), new byte[suite.publicKeyLength]));
    assertThrows(
        InvalidKeyException.class,
        () -> HpkePrivateKey.fromEncoded(suite.spec(), new byte[suite.seedLength]));
  }

  @Test
  public void rejectsMissingOrForeignParameters() throws Exception {
    final KeyPair kp = anyAvailableSuite().generateKeyPair();
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), (AlgorithmParameterSpec) null));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher().init(Cipher.DECRYPT_MODE, kp.getPrivate(), (AlgorithmParameterSpec) null));
    for (final int mode : new int[] {Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE}) {
      final Key key = mode == Cipher.ENCRYPT_MODE ? kp.getPublic() : kp.getPrivate();
      assertThrows(InvalidKeyException.class, () -> cipher().init(mode, key));
      assertThrows(
          InvalidKeyException.class, () -> cipher().init(mode, key, (AlgorithmParameters) null));
      final AlgorithmParameters gcm = AlgorithmParameters.getInstance("GCM");
      gcm.init(new GCMParameterSpec(128, new byte[12]));
      assertThrows(InvalidKeyException.class, () -> cipher().init(mode, key, gcm));
    }
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), new IvParameterSpec(new byte[16])));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void rejectsBadEncapsulation(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher().init(Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec()));
    for (final int delta : new int[] {-1, 1}) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () ->
              cipher()
                  .init(
                      Cipher.DECRYPT_MODE,
                      kp.getPrivate(),
                      suite.spec().withEncapsulation(new byte[suite.encLength + delta])));
    }
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () ->
            cipher()
                .init(
                    Cipher.ENCRYPT_MODE,
                    kp.getPublic(),
                    suite.spec().withEncapsulation(new byte[suite.encLength])));
  }

  @Test
  public void rejectsKeyOfAnotherSuite() throws Exception {
    final List<HpkeTestSuite> available = new ArrayList<>();
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      if (suite.isAvailable()) {
        available.add(suite);
      }
    }
    assumeTrue(available.size() > 1, "only one HPKE suite is available");
    for (final HpkeTestSuite keySuite : available) {
      final KeyPair kp = keySuite.generateKeyPair();
      for (final HpkeTestSuite specSuite : available) {
        if (specSuite == keySuite) {
          continue;
        }
        assertThrows(
            InvalidAlgorithmParameterException.class,
            () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), specSuite.spec()));
        assertThrows(
            InvalidAlgorithmParameterException.class,
            () ->
                cipher()
                    .init(
                        Cipher.DECRYPT_MODE,
                        kp.getPrivate(),
                        specSuite.spec().withEncapsulation(new byte[specSuite.encLength])));
      }
    }
  }

  @Test
  public void rejectsWrongKeyKindAndMode() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    final HpkeParameterSpec recipientSpec =
        suite.spec().withEncapsulation(new byte[suite.encLength]);
    assertThrows(
        InvalidKeyException.class,
        () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPrivate(), suite.spec()));
    assertThrows(
        InvalidKeyException.class,
        () -> cipher().init(Cipher.DECRYPT_MODE, kp.getPublic(), recipientSpec));
    for (final Key key : new Key[] {kp.getPublic(), kp.getPrivate()}) {
      assertThrows(
          UnsupportedOperationException.class,
          () -> cipher().init(Cipher.WRAP_MODE, key, suite.spec()));
      assertThrows(
          UnsupportedOperationException.class,
          () -> cipher().init(Cipher.UNWRAP_MODE, key, recipientSpec));
    }
  }

  @Test
  public void rejectsDestroyedPrivateKey() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    ((Destroyable) kp.getPrivate()).destroy();
    assertThrows(
        InvalidKeyException.class,
        () ->
            cipher()
                .init(
                    Cipher.DECRYPT_MODE,
                    kp.getPrivate(),
                    suite.spec().withEncapsulation(new byte[suite.encLength])));
  }

  @Test
  public void rejectsNonHpkeKeys() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final HpkeParameterSpec spec = suite.spec();
    for (final String algorithm : new String[] {"RSA", "EC"}) {
      final KeyPair foreign =
          KeyPairGenerator.getInstance(algorithm, NATIVE_PROVIDER).generateKeyPair();
      assertThrows(
          InvalidKeyException.class,
          () -> cipher().init(Cipher.ENCRYPT_MODE, foreign.getPublic(), spec));
      assertThrows(
          InvalidKeyException.class,
          () ->
              cipher()
                  .init(
                      Cipher.DECRYPT_MODE,
                      foreign.getPrivate(),
                      spec.withEncapsulation(new byte[suite.encLength])));
    }
  }

  @Test
  public void rejectsAccpMlKemKey() throws Exception {
    assumeTrue(
        NATIVE_PROVIDER.getService("KeyPairGenerator", "ML-KEM-768") != null,
        "ACCP does not register ML-KEM on this JVM");
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    suite.assumeAvailable();
    final KeyPair mlkem =
        KeyPairGenerator.getInstance("ML-KEM-768", NATIVE_PROVIDER).generateKeyPair();
    final InvalidKeyException forPublic =
        Assertions.assertThrows(
            InvalidKeyException.class,
            () -> cipher().init(Cipher.ENCRYPT_MODE, mlkem.getPublic(), suite.spec()));
    final InvalidKeyException forPrivate =
        Assertions.assertThrows(
            InvalidKeyException.class,
            () ->
                cipher()
                    .init(
                        Cipher.DECRYPT_MODE,
                        mlkem.getPrivate(),
                        suite.spec().withEncapsulation(new byte[suite.encLength])));
    assertMlKemKeyAdvice(forPublic, forPrivate);
  }

  /** Import advice must avoid internal class names and point senders to public-key import. */
  static void assertMlKemKeyAdvice(
      final InvalidKeyException forPublic, final InvalidKeyException forPrivate) {
    assertTrue(
        forPublic.getMessage().contains("HpkePublicKey.fromEncoded"), forPublic.getMessage());
    assertFalse(forPublic.getMessage().contains("seed"), forPublic.getMessage());
    assertTrue(
        forPrivate.getMessage().contains("HpkePrivateKey.fromEncoded"), forPrivate.getMessage());
    assertTrue(forPrivate.getMessage().contains("seed"), forPrivate.getMessage());
    for (final InvalidKeyException ex : new InvalidKeyException[] {forPublic, forPrivate}) {
      assertFalse(ex.getMessage().contains("EvpKem"), ex.getMessage());
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void tamperingIsDetected(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final HpkeParameterSpec spec = suite.spec().withInfo(INFO);
    final byte[][] sealed = seal(kp.getPublic(), spec, AAD, PLAINTEXT);
    final byte[] enc = sealed[0];
    final byte[] ct = sealed[1];
    assertArrayEquals(PLAINTEXT, open(kp.getPrivate(), spec, enc, AAD, ct));

    final byte[] badCt = ct.clone();
    badCt[0] ^= 1;
    assertThrows(AEADBadTagException.class, () -> open(kp.getPrivate(), spec, enc, AAD, badCt));
    final byte[] badTag = ct.clone();
    badTag[badTag.length - 1] ^= 1;
    assertThrows(AEADBadTagException.class, () -> open(kp.getPrivate(), spec, enc, AAD, badTag));
    assertThrows(
        AEADBadTagException.class,
        () -> open(kp.getPrivate(), spec, enc, AAD, Arrays.copyOf(ct, ct.length - 1)));
    assertThrows(
        AEADBadTagException.class, () -> open(kp.getPrivate(), spec, enc, AAD, new byte[0]));

    // ML-KEM decapsulation rejects implicitly, so a wrong enc of the right length passes init and
    // fails at doFinal.
    final byte[] badEnc = enc.clone();
    badEnc[0] ^= 1;
    assertThrows(AEADBadTagException.class, () -> open(kp.getPrivate(), spec, badEnc, AAD, ct));

    assertThrows(
        AEADBadTagException.class,
        () -> open(kp.getPrivate(), suite.spec().withInfo(AAD), enc, AAD, ct));
    assertThrows(
        AEADBadTagException.class, () -> open(kp.getPrivate(), suite.spec(), enc, AAD, ct));
    assertThrows(AEADBadTagException.class, () -> open(kp.getPrivate(), spec, enc, INFO, ct));
    assertThrows(AEADBadTagException.class, () -> open(kp.getPrivate(), spec, enc, null, ct));

    final PrivateKey other = suite.generateKeyPair().getPrivate();
    assertThrows(AEADBadTagException.class, () -> open(other, spec, enc, AAD, ct));
  }

  @Test
  public void reinitResetsState() throws Exception {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] enc1 = sender.getIV();
    assertNotNull(enc1);
    sender.updateAAD(AAD);
    final byte[] first = sender.doFinal(PLAINTEXT);
    sender.updateAAD(AAD);
    sender.update(PLAINTEXT);
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] enc2 = sender.getIV();
    assertFalse(Arrays.equals(enc1, enc2));
    final byte[] ct = sender.doFinal(PLAINTEXT);
    assertEquals(PLAINTEXT.length + HpkeTestSuite.AEAD_OVERHEAD, ct.length);
    assertArrayEquals(PLAINTEXT, open(kp.getPrivate(), suite.spec(), enc2, null, ct));

    final byte[] ct1 = sender.doFinal(PLAINTEXT);
    final Cipher recipient = recipient(suite, kp, enc2);
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct));
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct1));
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(enc2));
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct));
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(first));
  }

  @Test
  public void wrapAndUnwrapModesFailBeforeTheSuiteCheck() throws Exception {
    final KeyPair kp = anyAvailableSuite().generateKeyPair();
    // Unsupported wrapping modes take precedence over suite validation.
    for (final HpkeParameterSpec spec :
        new HpkeParameterSpec[] {
          HpkeParameterSpec.of(0x0020, 0x0001, 0x0001), HpkeParameterSpec.of(0x0041, 0x0001, 0xFFFF)
        }) {
      for (final Key key : new Key[] {kp.getPublic(), kp.getPrivate()}) {
        assertThrows(
            UnsupportedOperationException.class, () -> cipher().init(Cipher.WRAP_MODE, key, spec));
        assertThrows(
            UnsupportedOperationException.class,
            () -> cipher().init(Cipher.UNWRAP_MODE, key, spec));
      }
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void senderSetupFailureIsInvalidKeyException(final HpkeTestSuite suite) throws Throwable {
    suite.assumeAvailable();
    // Bypass fromEncoded's modulus check to test AWS-LC's sender-setup validation.
    final byte[] bad = new byte[suite.publicKeyLength];
    Arrays.fill(bad, (byte) 0xFF);
    final PublicKey badKey =
        (PublicKey)
            TestUtil.sneakyConstruct(
                "com.amazon.corretto.crypto.provider.HpkePublicKey", suite.accpSuite(), bad);
    final Cipher sender = cipher();
    final InvalidKeyException ex =
        Assertions.assertThrows(
            InvalidKeyException.class,
            () -> sender.init(Cipher.ENCRYPT_MODE, badKey, suite.spec()));
    assertEquals(InvalidKeyException.class, ex.getClass());
    assertNull(sender.getIV());
    final KeyPair kp = suite.generateKeyPair();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] ct = sender.doFinal(PLAINTEXT);
    assertArrayEquals(PLAINTEXT, open(kp.getPrivate(), suite.spec(), sender.getIV(), null, ct));
  }

  public static List<Arguments> overlapParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      // {inputOffset, outputOffset}: output overlapping the input from before ({40, 3}) or after
      // ({3, 40}, {3, 30}), exactly at the input ({17, 17}), and disjoint from it ({0, 200}).
      for (final int[] offsets : new int[][] {{40, 3}, {3, 40}, {3, 30}, {17, 17}, {0, 200}}) {
        result.add(Arguments.of(suite, offsets[0], offsets[1]));
      }
    }
    return result;
  }

  @ParameterizedTest
  @MethodSource("overlapParams")
  public void overlappingInputAndOutput(
      final HpkeTestSuite suite, final int inOfs, final int outOfs) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    final byte[] plaintext = new byte[100];
    new Random(7).nextBytes(plaintext);
    final byte[] buf = new byte[Math.max(inOfs, outOfs) + plaintext.length + tag];

    System.arraycopy(plaintext, 0, buf, inOfs, plaintext.length);
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    sender.updateAAD(AAD);
    assertEquals(plaintext.length + tag, sender.doFinal(buf, inOfs, plaintext.length, buf, outOfs));
    final byte[] ct = Arrays.copyOfRange(buf, outOfs, outOfs + plaintext.length + tag);
    assertArrayEquals(plaintext, open(kp.getPrivate(), suite.spec(), sender.getIV(), AAD, ct));

    Arrays.fill(buf, (byte) 0);
    System.arraycopy(ct, 0, buf, inOfs, ct.length);
    final Cipher recipient = cipher();
    recipient.init(
        Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(sender.getIV()));
    recipient.updateAAD(AAD);
    assertEquals(plaintext.length, recipient.doFinal(buf, inOfs, ct.length, buf, outOfs));
    assertArrayEquals(plaintext, Arrays.copyOfRange(buf, outOfs, outOfs + plaintext.length));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void failedInPlaceOpenZeroesOutputRange(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] ct = sender.doFinal(PLAINTEXT);
    final int off = 5;
    final byte[] buf = new byte[off + ct.length + 3];
    Arrays.fill(buf, (byte) 0x5A);
    System.arraycopy(ct, 0, buf, off, ct.length);
    buf[off + ct.length - 1] ^= 1;
    final byte[] expected = buf.clone();
    Arrays.fill(expected, off, off + ct.length - tag, (byte) 0);
    final Cipher recipient = recipient(suite, kp, sender.getIV());
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(buf, off, ct.length, buf, off));
    // The output range, here the start of the caller's ciphertext, is zeroed; nothing else changes.
    assertArrayEquals(expected, buf);
    // The context is unchanged, so an intact copy of the message still opens.
    assertArrayEquals(PLAINTEXT, recipient.doFinal(ct));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void shortBufferKeepsBufferedInputAndAad(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    final byte[] part1 = Arrays.copyOfRange(PLAINTEXT, 0, 10);
    final byte[] part2 = Arrays.copyOfRange(PLAINTEXT, 10, PLAINTEXT.length);
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    sender.updateAAD(AAD);
    sender.update(part1);
    assertThrows(
        ShortBufferException.class,
        () -> sender.doFinal(part2, 0, part2.length, new byte[PLAINTEXT.length + tag - 1]));
    final byte[] ct0 = new byte[PLAINTEXT.length + tag];
    assertEquals(ct0.length, sender.doFinal(part2, 0, part2.length, ct0));
    final byte[] ct1 = sender.doFinal(message(1));

    final byte[] ctPart1 = Arrays.copyOfRange(ct0, 0, 10);
    final byte[] ctPart2 = Arrays.copyOfRange(ct0, 10, ct0.length);
    final Cipher recipient = recipient(suite, kp, sender.getIV());
    recipient.updateAAD(AAD);
    recipient.update(ctPart1);
    assertThrows(
        ShortBufferException.class,
        () -> recipient.doFinal(ctPart2, 0, ctPart2.length, new byte[PLAINTEXT.length - 1]));
    final byte[] pt0 = new byte[PLAINTEXT.length];
    assertEquals(pt0.length, recipient.doFinal(ctPart2, 0, ctPart2.length, pt0));
    assertArrayEquals(PLAINTEXT, pt0);
    // The short buffer did not advance the sequence number, so the next message opens too.
    assertArrayEquals(message(1), recipient.doFinal(ct1));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void doFinalReturnsExactlySizedArrays(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final int[] sizes = {0, 1, 15, 16, 17, 4096};
    final byte[][] cts = new byte[sizes.length][];
    for (int i = 0; i < sizes.length; i++) {
      cts[i] = sender.doFinal(new byte[sizes[i]]);
      assertEquals(sizes[i] + HpkeTestSuite.AEAD_OVERHEAD, cts[i].length);
    }
    final Cipher recipient = cipher();
    recipient.init(
        Cipher.DECRYPT_MODE, kp.getPrivate(), suite.spec().withEncapsulation(sender.getIV()));
    for (int i = 0; i < sizes.length; i++) {
      assertArrayEquals(new byte[sizes[i]], recipient.doFinal(cts[i]));
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void messagesOpenInOrder(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[][] cts = new byte[5][];
    for (int i = 0; i < cts.length; i++) {
      sender.updateAAD(aad(i));
      cts[i] = sender.doFinal(message(i));
    }
    final byte[] again = sender.doFinal(message(0));
    assertFalse(Arrays.equals(cts[0], again));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    for (int i = 0; i < cts.length; i++) {
      recipient.updateAAD(aad(i));
      assertArrayEquals(message(i), recipient.doFinal(cts[i]));
    }
    assertArrayEquals(message(0), recipient.doFinal(again));
  }

  /**
   * Checks RFC 9180 failed-open retries and message-loss behavior in README's HPKE Considerations.
   */
  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void outOfOrderAndSkippedMessagesFailWithoutAdvancing(final HpkeTestSuite suite)
      throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] c0 = sender.doFinal(message(0));
    final byte[] c1 = sender.doFinal(message(1));
    final byte[] c2 = sender.doFinal(message(2));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(c1));
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(c2));
    assertArrayEquals(message(0), recipient.doFinal(c0));
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(c0));
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(c2));
    assertArrayEquals(message(1), recipient.doFinal(c1));
    assertArrayEquals(message(2), recipient.doFinal(c2));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void updateThenDoFinalAcrossMessages(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[][] cts = new byte[3][];
    for (int i = 0; i < cts.length; i++) {
      final byte[] m = message(i);
      sender.updateAAD(aad(i));
      final byte[] out = sender.update(m, 0, 3);
      assertTrue(out == null || out.length == 0);
      cts[i] = sender.doFinal(m, 3, m.length - 3);
      assertEquals(m.length + HpkeTestSuite.AEAD_OVERHEAD, cts[i].length);
    }
    final Cipher recipient = recipient(suite, kp, sender.getIV());
    for (int i = 0; i < cts.length; i++) {
      recipient.updateAAD(aad(i));
      final byte[] out = recipient.update(cts[i], 0, 5);
      assertTrue(out == null || out.length == 0);
      assertArrayEquals(message(i), recipient.doFinal(cts[i], 5, cts[i].length - 5));
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void failedDoFinalResetsBufferedInputAndAad(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    sender.updateAAD(AAD);
    final byte[] c0 = sender.doFinal(message(0));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    final byte[] tampered = c0.clone();
    tampered[tampered.length - 1] ^= 1;
    recipient.updateAAD(AAD);
    recipient.update(tampered, 0, 4);
    assertThrows(
        AEADBadTagException.class, () -> recipient.doFinal(tampered, 4, tampered.length - 4));
    // Had the failed call kept its AAD or buffered prefix, this open would fail.
    recipient.updateAAD(AAD);
    assertArrayEquals(message(0), recipient.doFinal(c0));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void updateAadAfterUpdateThrows(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    sender.updateAAD(AAD);
    sender.update(message(0));
    assertThrows(IllegalStateException.class, () -> sender.updateAAD(AAD));
    final byte[] c0 = sender.doFinal();
    sender.updateAAD(AAD);
    final byte[] c1 = sender.doFinal(message(1));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    recipient.updateAAD(AAD);
    recipient.update(c0);
    assertThrows(IllegalStateException.class, () -> recipient.updateAAD(AAD));
    assertArrayEquals(message(0), recipient.doFinal());
    recipient.updateAAD(AAD);
    assertArrayEquals(message(1), recipient.doFinal(c1));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void outputSizeIncludesBufferedInput(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    assertEquals(tag, sender.getOutputSize(0));
    sender.update(new byte[10]);
    assertEquals(10 + 5 + tag, sender.getOutputSize(5));
    final byte[] ct = sender.doFinal(new byte[5]);
    assertEquals(10 + 5 + tag, ct.length);
    assertEquals(tag, sender.getOutputSize(0));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    assertEquals(0, recipient.getOutputSize(0));
    assertEquals(0, recipient.getOutputSize(tag - 1));
    recipient.update(ct, 0, 8);
    assertEquals(0, recipient.getOutputSize(0));
    assertEquals(ct.length - tag, recipient.getOutputSize(ct.length - 8));
    assertArrayEquals(new byte[15], recipient.doFinal(ct, 8, ct.length - 8));
    assertEquals(0, recipient.getOutputSize(0));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void shortCiphertextFailsWithoutAdvancing(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[] c0 = sender.doFinal(message(0));

    final Cipher recipient = recipient(suite, kp, sender.getIV());
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(new byte[tag - 1]));
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal());
    // Shorter than a tag in total, even though split across update and doFinal.
    recipient.update(c0, 0, 8);
    assertThrows(AEADBadTagException.class, () -> recipient.doFinal(c0, 8, tag - 9));
    assertArrayEquals(message(0), recipient.doFinal(c0));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void fiveArgumentUpdateAndOutputOnlyDoFinal(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final int tag = HpkeTestSuite.AEAD_OVERHEAD;
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[][] cts = new byte[2][];
    for (int i = 0; i < cts.length; i++) {
      final byte[] m = message(i);
      final byte[] out = new byte[3 + m.length + tag];
      assertEquals(0, sender.update(m, 0, 4, out, 3));
      assertEquals(0, sender.update(m, 4, m.length - 4, out, 3));
      assertEquals(m.length + tag, sender.doFinal(out, 3));
      cts[i] = Arrays.copyOfRange(out, 3, out.length);
    }
    final Cipher recipient = recipient(suite, kp, sender.getIV());
    for (int i = 0; i < cts.length; i++) {
      final byte[] m = message(i);
      final byte[] out = new byte[2 + m.length];
      assertEquals(0, recipient.update(cts[i], 0, 5, out, 2));
      assertEquals(0, recipient.update(cts[i], 5, cts[i].length - 5, out, 2));
      assertEquals(m.length, recipient.doFinal(out, 2));
      assertArrayEquals(m, Arrays.copyOfRange(out, 2, out.length));
    }
  }

  private static byte[] readFully(final CipherInputStream in) throws IOException {
    final ByteArrayOutputStream result = new ByteArrayOutputStream();
    final byte[] chunk = new byte[7];
    int n;
    while ((n = in.read(chunk)) != -1) {
      result.write(chunk, 0, n);
    }
    return result.toByteArray();
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void cipherStreamsAcrossMessages(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    final KeyPair kp = suite.generateKeyPair();
    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
    final byte[][] cts = new byte[2][];
    for (int i = 0; i < cts.length; i++) {
      final byte[] m = message(i);
      final ByteArrayOutputStream sink = new ByteArrayOutputStream();
      if (i == 1) {
        sender.updateAAD(aad(i));
      }
      try (CipherOutputStream out = new CipherOutputStream(sink, sender)) {
        out.write(m, 0, 2);
        out.write(m[2]);
        out.write(m, 3, m.length - 3);
      }
      cts[i] = sink.toByteArray();
      assertEquals(m.length + HpkeTestSuite.AEAD_OVERHEAD, cts[i].length);
    }
    final Cipher recipient = recipient(suite, kp, sender.getIV());
    for (int i = 0; i < cts.length; i++) {
      if (i == 1) {
        recipient.updateAAD(aad(i));
      }
      try (CipherInputStream in =
          new CipherInputStream(new ByteArrayInputStream(cts[i]), recipient)) {
        assertArrayEquals(message(i), readFully(in), "message " + i);
      }
    }
  }

  private static void randomUpdate(
      final Cipher c,
      final byte[] data,
      final int off,
      final int len,
      final Random rnd,
      final ByteArrayOutputStream collected)
      throws Exception {
    final int size = c.getOutputSize(len);
    switch (rnd.nextInt(5)) {
      case 0:
        {
          final byte[] out = c.update(Arrays.copyOfRange(data, off, off + len));
          if (out != null) {
            collected.write(out, 0, out.length);
          }
          break;
        }
      case 1:
        {
          final byte[] out = c.update(data, off, len);
          if (out != null) {
            collected.write(out, 0, out.length);
          }
          break;
        }
      case 2:
        {
          final byte[] out = new byte[size];
          final int n = c.update(data, off, len, out);
          collected.write(out, 0, n);
          break;
        }
      case 3:
        {
          final int outOff = rnd.nextInt(5);
          final byte[] out = new byte[outOff + size];
          final int n = c.update(data, off, len, out, outOff);
          collected.write(out, outOff, n);
          break;
        }
      default:
        {
          final boolean direct = rnd.nextBoolean();
          final ByteBuffer out =
              direct ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);
          c.update(inputBuffer(data, off, len, direct), out);
          drain(out, collected);
          break;
        }
    }
  }

  /**
   * {@code data[off, off + len)} as a ByteBuffer: wrapped, or a direct copy (which the JDK's
   * default CipherSpi path processes in chunks of at most 4 KiB).
   */
  private static ByteBuffer inputBuffer(
      final byte[] data, final int off, final int len, final boolean direct) {
    if (!direct) {
      return ByteBuffer.wrap(data, off, len);
    }
    final ByteBuffer in = ByteBuffer.allocateDirect(len);
    in.put(data, off, len);
    in.flip();
    return in;
  }

  private static void drain(final ByteBuffer out, final ByteArrayOutputStream collected) {
    out.flip();
    final byte[] bytes = new byte[out.remaining()];
    out.get(bytes);
    collected.write(bytes, 0, bytes.length);
  }

  private static void randomUpdateAad(final Cipher c, final byte[] aad, final Random rnd) {
    final int split = rnd.nextInt(aad.length + 1);
    if (rnd.nextBoolean()) {
      c.updateAAD(aad, 0, split);
      c.updateAAD(Arrays.copyOfRange(aad, split, aad.length));
    } else {
      c.updateAAD(ByteBuffer.wrap(aad, 0, split));
      c.updateAAD(inputBuffer(aad, split, aad.length - split, rnd.nextBoolean()));
    }
  }

  /** Exercises random splits and overloads, including buffered AAD and data. */
  private static byte[] randomMessage(
      final Cipher c, final byte[] aad, final byte[] data, final Random rnd) throws Exception {
    final ByteArrayOutputStream collected = new ByteArrayOutputStream();
    if (aad != null) {
      randomUpdateAad(c, aad, rnd);
    }
    int pos = 0;
    for (int updates = rnd.nextInt(4); updates > 0 && pos < data.length; updates--) {
      final int len = rnd.nextInt(data.length - pos + 1);
      randomUpdate(c, data, pos, len, rnd, collected);
      pos += len;
    }
    final int len = data.length - pos;
    final int size = c.getOutputSize(len);
    switch (rnd.nextInt(7)) {
      case 0:
        {
          randomUpdate(c, data, pos, len, rnd, collected);
          final byte[] out = c.doFinal();
          collected.write(out, 0, out.length);
          break;
        }
      case 1:
        {
          final byte[] out = c.doFinal(Arrays.copyOfRange(data, pos, pos + len));
          collected.write(out, 0, out.length);
          break;
        }
      case 2:
        {
          final byte[] out = c.doFinal(data, pos, len);
          collected.write(out, 0, out.length);
          break;
        }
      case 3:
        {
          final byte[] out = new byte[size];
          final int n = c.doFinal(data, pos, len, out);
          collected.write(out, 0, n);
          break;
        }
      case 4:
        {
          final int outOff = rnd.nextInt(5);
          final byte[] out = new byte[outOff + size];
          final int n = c.doFinal(data, pos, len, out, outOff);
          collected.write(out, outOff, n);
          break;
        }
      case 5:
        {
          randomUpdate(c, data, pos, len, rnd, collected);
          final int outOff = rnd.nextInt(5);
          final byte[] out = new byte[outOff + c.getOutputSize(0)];
          final int n = c.doFinal(out, outOff);
          collected.write(out, outOff, n);
          break;
        }
      default:
        {
          final boolean direct = rnd.nextBoolean();
          final ByteBuffer out =
              direct ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);
          c.doFinal(inputBuffer(data, pos, len, direct), out);
          drain(out, collected);
          break;
        }
    }
    return collected.toByteArray();
  }

  @Test
  public void randomizedSplitsAcrossOverloads() throws Exception {
    final List<HpkeTestSuite> suites = new ArrayList<>();
    for (final HpkeTestSuite suite : HpkeTestSuite.values()) {
      if (suite.isAvailable()) {
        suites.add(suite);
      }
    }
    assumeTrue(!suites.isEmpty(), "the linked AWS-LC provides no HPKE suite");
    final KeyPair[] pairs = new KeyPair[suites.size()];
    for (int i = 0; i < pairs.length; i++) {
      pairs[i] = suites.get(i).generateKeyPair();
    }
    final Random rnd = new Random(0x48504B45L);
    for (int c = 0; c < 300; c++) {
      final HpkeTestSuite suite = suites.get(c % suites.size());
      final KeyPair kp = pairs[c % suites.size()];
      final Cipher sender = cipher();
      sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec());
      final byte[][] messages = new byte[3][];
      final byte[][] aads = new byte[3][];
      final byte[][] cts = new byte[3][];
      for (int m = 0; m < messages.length; m++) {
        // About 1 in 20 messages is near 10 KiB, past the JDK's 4 KiB direct-buffer chunks.
        messages[m] = new byte[rnd.nextInt(20) == 0 ? 8192 + rnd.nextInt(2049) : rnd.nextInt(2049)];
        rnd.nextBytes(messages[m]);
        if (rnd.nextBoolean()) {
          aads[m] = new byte[rnd.nextInt(65)];
          rnd.nextBytes(aads[m]);
        }
        cts[m] = randomMessage(sender, aads[m], messages[m], rnd);
        assertEquals(
            messages[m].length + HpkeTestSuite.AEAD_OVERHEAD,
            cts[m].length,
            "sealed length, case " + c + " message " + m + " " + suite);
      }
      final Cipher recipient = recipient(suite, kp, sender.getIV());
      for (int m = 0; m < messages.length; m++) {
        assertArrayEquals(
            messages[m],
            randomMessage(recipient, aads[m], cts[m], rnd),
            "opened, case " + c + " message " + m + " " + suite);
      }
    }
  }

  private static int capacity(final Object spi, final String field) throws Throwable {
    return ((byte[]) TestUtil.sneakyInvoke(TestUtil.sneakyGetField(spi, field), "getDataBuffer"))
        .length;
  }

  @Test
  public void largeMessageBufferIsNotRetained() throws Throwable {
    final HpkeTestSuite suite = anyAvailableSuite();
    final KeyPair kp = suite.generateKeyPair();
    // The SPI is used directly: reflection into javax.crypto.Cipher is not possible on JDK 17+.
    final Object spi =
        TestUtil.sneakyConstruct(TestUtil.NATIVE_PROVIDER_PACKAGE + ".HpkeCipher", NATIVE_PROVIDER);
    TestUtil.sneakyInvoke(
        spi, "engineInit", Cipher.ENCRYPT_MODE, kp.getPublic(), suite.spec(), (SecureRandom) null);
    final int retained = 64 * 1024;
    final byte[][] cts = new byte[3][];
    final byte[][] messages = {new byte[1024], new byte[200 * 1024], new byte[1024]};
    for (int i = 0; i < messages.length; i++) {
      new Random(i).nextBytes(messages[i]);
      TestUtil.sneakyInvoke(spi, "engineUpdateAAD", messages[i], 0, messages[i].length);
      TestUtil.sneakyInvoke(spi, "engineUpdate", messages[i], 0, messages[i].length);
      cts[i] = TestUtil.sneakyInvoke(spi, "engineDoFinal", new byte[0], 0, 0);
      assertEquals(messages[i].length + HpkeTestSuite.AEAD_OVERHEAD, cts[i].length);
      for (final String field : new String[] {"buffer_", "aad_"}) {
        final int capacity = capacity(spi, field);
        if (messages[i].length > retained) {
          assertTrue(capacity <= retained, field + " " + capacity);
        } else {
          assertTrue(capacity > 0 && capacity <= retained, field + " " + capacity);
        }
      }
    }
    final byte[] enc = TestUtil.sneakyInvoke(spi, "engineGetIV");
    final Cipher recipient = recipient(suite, kp, enc);
    for (int i = 0; i < messages.length; i++) {
      recipient.updateAAD(messages[i]);
      assertArrayEquals(messages[i], recipient.doFinal(cts[i]), "message " + i);
    }
  }
}
