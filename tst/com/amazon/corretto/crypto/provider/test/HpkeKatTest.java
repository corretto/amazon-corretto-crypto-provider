// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import com.amazon.corretto.crypto.utils.HpkeUtils;
import java.util.Arrays;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.crypto.Cipher;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * HPKE base-mode known-answer tests, one per curated ML-KEM suite, from hpke_base_kat.txt alongside
 * this class: the draft-ietf-hpke-pq-05 vectors as vendored by AWS-LC
 * (crypto/hpke/hpke_test_vectors_pq.txt), with all ten encryptions of each vector. They are
 * draft-sourced and may churn with the draft.
 *
 * <p>{@link NativeTestHooks#hpkeSealWithSeedForTesting} supplies deterministic encapsulation. A
 * public Cipher opens all ten ciphertexts on one context to check sequence numbering.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeKatTest {
  /** Encryptions per vector, at sequence numbers 0..9. */
  private static final int ENCRYPTIONS = 10;

  public static Stream<Arguments> vectors() throws Exception {
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(
                RspTestEntry.iterateOverLocalTests("hpke_base_kat.txt"), Spliterator.ORDERED),
            false)
        .map(
            entry ->
                Arguments.of(
                    new Vector(entry),
                    String.format(
                        "kem=%s kdf=%s aead=%s",
                        entry.getInstance("kem_id"),
                        entry.getInstance("kdf_id"),
                        entry.getInstance("aead_id"))));
  }

  /** One base-mode vector with its ten encryptions. */
  static final class Vector {
    final HpkeTestSuite suite;
    final byte[] info;
    final byte[] skRm;
    final byte[] pkRm;
    final byte[] ikmE;
    final byte[] enc;
    final byte[][] aad = new byte[ENCRYPTIONS][];
    final byte[][] ct = new byte[ENCRYPTIONS][];
    final byte[][] pt = new byte[ENCRYPTIONS][];

    Vector(final RspTestEntry entry) {
      assertEquals("0", entry.getInstance("mode"), "base mode only");
      suite =
          HpkeTestSuite.of(
              Integer.parseInt(entry.getInstance("kem_id")),
              Integer.parseInt(entry.getInstance("kdf_id")),
              Integer.parseInt(entry.getInstance("aead_id")));
      assertNotNull(suite, "vector for a suite ACCP does not curate: " + entry);
      info = entry.getInstanceFromHex("info");
      skRm = entry.getInstanceFromHex("skRm");
      pkRm = entry.getInstanceFromHex("pkRm");
      ikmE = entry.getInstanceFromHex("ikmE");
      enc = entry.getInstanceFromHex("enc");
      for (int i = 0; i < ENCRYPTIONS; i++) {
        aad[i] = entry.getInstanceFromHex("aad_" + i);
        ct[i] = entry.getInstanceFromHex("ct_" + i);
        pt[i] = entry.getInstanceFromHex("pt_" + i);
      }
    }

    @Override
    public String toString() {
      return suite.toString();
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("vectors")
  public void vectorLengths(final Vector v, final String name) {
    v.suite.assumeAvailable();
    assertEquals(v.suite.seedLength, v.skRm.length);
    assertEquals(v.suite.publicKeyLength, v.pkRm.length);
    assertEquals(v.suite.encLength, v.enc.length);
    // ML-KEM's encapsulation randomness is 32 bytes for every parameter set.
    assertEquals(32, v.ikmE.length);
    for (int i = 0; i < ENCRYPTIONS; i++) {
      assertEquals(v.pt[i].length + HpkeTestSuite.AEAD_OVERHEAD, v.ct[i].length);
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("vectors")
  public void senderKat(final Vector v, final String name) throws Throwable {
    v.suite.assumeAvailable();
    final HpkePrivateKey skR = HpkePrivateKey.fromEncoded(v.suite.namedSpec(), v.skRm);
    assertArrayEquals(v.pkRm, skR.getPublicKey().getEncoded());
    final byte[] enc = new byte[v.suite.encLength];
    final byte[][] ct =
        NativeTestHooks.hpkeSealWithSeedForTesting(
            v.suite.kemId, v.suite.kdfId, v.suite.aeadId, v.pkRm, v.info, v.ikmE, v.aad, v.pt, enc);
    assertArrayEquals(v.enc, enc);
    assertEquals(ENCRYPTIONS, ct.length);
    for (int i = 0; i < ENCRYPTIONS; i++) {
      assertArrayEquals(v.ct[i], ct[i], "encryption " + i);
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("vectors")
  public void recipientKat(final Vector v, final String name) throws Exception {
    v.suite.assumeAvailable();
    final HpkePrivateKey skR = HpkePrivateKey.fromEncoded(v.suite.namedSpec(), v.skRm);
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(
        Cipher.DECRYPT_MODE,
        skR,
        HpkeParameterSpec.of(v.suite.kemId, v.suite.kdfId, v.suite.aeadId)
            .withInfo(v.info)
            .withEncapsulation(v.enc));
    for (int i = 0; i < ENCRYPTIONS; i++) {
      recipient.updateAAD(v.aad[i]);
      assertArrayEquals(v.pt[i], recipient.doFinal(v.ct[i]), "encryption " + i);
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("vectors")
  public void importedPublicKeyRoundTrip(final Vector v, final String name) throws Exception {
    v.suite.assumeAvailable();
    final HpkePublicKey pkR = HpkePublicKey.fromEncoded(v.suite.namedSpec(), v.pkRm);
    final HpkePrivateKey skR = HpkePrivateKey.fromEncoded(v.suite.namedSpec(), v.skRm);
    final HpkeParameterSpec spec =
        HpkeParameterSpec.of(v.suite.kemId, v.suite.kdfId, v.suite.aeadId).withInfo(v.info);
    final Cipher sender = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    sender.init(Cipher.ENCRYPT_MODE, pkR, spec);
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(Cipher.DECRYPT_MODE, skR, spec.withEncapsulation(sender.getIV()));
    for (int i = 0; i < ENCRYPTIONS; i++) {
      sender.updateAAD(v.aad[i]);
      final byte[] ct = sender.doFinal(v.pt[i]);
      recipient.updateAAD(v.aad[i]);
      assertArrayEquals(v.pt[i], recipient.doFinal(ct));
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("vectors")
  public void hpkeUtilsOpensVectorFraming(final Vector v, final String name) throws Exception {
    v.suite.assumeAvailable();
    final byte[] framed = concat(v.enc, v.ct[0]);
    final HpkePrivateKey skR = HpkePrivateKey.fromEncoded(v.suite.namedSpec(), v.skRm);
    assertArrayEquals(v.pt[0], HpkeUtils.open(skR, v.info, v.aad[0], framed));
  }

  private static byte[] concat(final byte[] a, final byte[] b) {
    final byte[] result = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, result, a.length, b.length);
    return result;
  }
}
