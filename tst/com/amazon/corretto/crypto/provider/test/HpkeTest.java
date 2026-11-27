// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.HpkeTestSuite.cipher;
import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.amazon.corretto.crypto.provider.HpkeKey;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import com.amazon.corretto.crypto.provider.HpkeSpec;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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

/** HPKE Cipher, KeyPairGenerator, keys, and parameters, for every curated suite. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeTest {
  private static final byte[] INFO = "HPKE test info".getBytes(StandardCharsets.UTF_8);
  private static final byte[] AAD = "HPKE test aad".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PLAINTEXT =
      "Beauty is truth, truth beauty".getBytes(StandardCharsets.UTF_8);

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
      final HpkeSpec spec,
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
  public void rejectsUncuratedSuite() throws Exception {
    final KeyPair kp = anyAvailableSuite().generateKeyPair();
    for (final HpkeSpec spec :
        new HpkeSpec[] {
          // Valid RFC 9180 suites with classical KEMs, which ACCP does not offer.
          HpkeSpec.of(0x0020, 0x0001, 0x0001),
          HpkeSpec.of(0x0010, 0x0001, 0x0001),
          // Curated KEMs with another KDF or AEAD.
          HpkeSpec.of(0x0041, 0x0002, 0x0002),
          HpkeSpec.of(0x0042, 0x0001, 0x0001),
          // Export-only AEAD.
          HpkeSpec.of(0x0041, 0x0001, 0xFFFF),
          // An ML-KEM KEM id that ACCP does not curate.
          HpkeSpec.of(0x0040, 0x0001, 0x0001),
        }) {
      assertThrows(
          InvalidAlgorithmParameterException.class,
          () -> cipher().init(Cipher.ENCRYPT_MODE, kp.getPublic(), spec));
    }
    final HpkeSpec uncurated = HpkeSpec.of(0x0040, 0x0001, 0x0001);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> KeyPairGenerator.getInstance("HPKE", NATIVE_PROVIDER).initialize(uncurated));
    assertThrows(
        InvalidKeyException.class, () -> HpkePublicKey.fromEncoded(uncurated, new byte[800]));
    assertThrows(
        InvalidKeyException.class, () -> HpkePrivateKey.fromEncoded(uncurated, new byte[64]));
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
    final HpkeSpec recipientSpec = suite.spec().withEncapsulation(new byte[suite.encLength]);
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
    final HpkeSpec spec = suite.spec();
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

  @Test
  public void generatorRequiresHpkeSpec() throws Exception {
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

  private static final HpkeSpec SUITE = HpkeSpec.ML_KEM_768_HKDF_SHA256_AES_128_GCM;
  private static final String JDK_SPEC_CLASS = "javax.crypto.spec.HPKEParameterSpec";
  private static final byte[] EMPTY = new byte[0];

  @Test
  public void ofAcceptsAnyIdInRangeButRejectsOutOfRange() {
    HpkeSpec.of(0, 0, 0);
    HpkeSpec.of(0xFFFF, 0xFFFF, 0xFFFF);
    for (final int invalid : new int[] {-1, 0x10000}) {
      assertEquals(
          "kem_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class, () -> HpkeSpec.of(invalid, invalid, invalid))
              .getMessage());
      assertEquals(
          "kdf_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class, () -> HpkeSpec.of(0x41, invalid, invalid))
              .getMessage());
      assertEquals(
          "aead_id must be in [0, 65535]: " + invalid,
          Assertions.assertThrows(
                  IllegalArgumentException.class, () -> HpkeSpec.of(0x41, 1, invalid))
              .getMessage());
    }
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
    final HpkeSpec withInfo = SUITE.withInfo(info);
    final HpkeSpec withBoth = withInfo.withEncapsulation(enc);

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
    final HpkeSpec a = SUITE.withInfo(new byte[] {1}).withEncapsulation(new byte[2]);
    final HpkeSpec b =
        HpkeSpec.of(0x0041, 0x0001, 0x0001).withInfo(new byte[] {1}).withEncapsulation(new byte[2]);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(a, SUITE);
    assertNotEquals(a, a.withInfo(new byte[] {2}));
    assertNotEquals(a, a.withEncapsulation(new byte[3]));
    assertNotEquals(SUITE, HpkeSpec.of(0x0041, 0x0002, 0x0001));
    assertNotEquals(SUITE, SUITE.withEncapsulation(new byte[0]));
  }

  private static HpkeSpec fromComponents(
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
        HpkeSpec.class, "fromComponents", kem, kdf, aead, info, enc, psk, pskId, authKey);
  }

  private static HpkeSpec from(final AlgorithmParameterSpec params) throws Throwable {
    return sneakyInvoke(HpkeSpec.class, "from", params);
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
    final HpkeSpec spec =
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
    final HpkeSpec spec =
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
  public void unadaptableJdkSpecSaysWhy() throws Throwable {
    final List<String> names = new ArrayList<>(Arrays.asList("kem_id", "zeta", "info", "alpha"));
    final List<String> unknown =
        TestUtil.sneakyInvoke(HpkeSpec.class, "unknownJdkSpecMethods", (Object) names);
    assertEquals(Arrays.asList("alpha", "zeta"), unknown);
    final String message =
        TestUtil.sneakyInvoke(HpkeSpec.class, "unadaptableJdkSpecMessage", (Object) unknown);
    assertEquals(
        "ACCP does not recognize method(s) [alpha, zeta] of "
            + JDK_SPEC_CLASS
            + " on this JDK;"
            + " use com.amazon.corretto.crypto.provider.HpkeSpec or upgrade ACCP",
        message);
    final String unreadable =
        TestUtil.sneakyInvoke(HpkeSpec.class, "unadaptableJdkSpecMessage", (Object) null);
    assertTrue(unreadable.startsWith("ACCP cannot read " + JDK_SPEC_CLASS), unreadable);
    assertTrue(unreadable.endsWith("or upgrade ACCP"), unreadable);
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
}
