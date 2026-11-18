// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.amazon.corretto.crypto.provider.HpkeParameterSpec;
import com.amazon.corretto.crypto.provider.HpkePrivateKey;
import com.amazon.corretto.crypto.provider.HpkePublicKey;
import com.amazon.corretto.crypto.utils.HpkeUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** The {@code enc || ct} helpers in {@link HpkeUtils}, for every curated suite. */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeUtilsTest {
  private static final String DECRYPTION_FAILED = "HPKE decryption failed";
  private static final byte[] INFO = {1, 2, 3};
  private static final byte[] AAD = {4, 5, 6, 7};
  private static final byte[] PLAINTEXT = "yellow submarine".getBytes(StandardCharsets.UTF_8);

  private static final class Keys {
    final HpkePublicKey pub;
    final HpkePrivateKey priv;

    Keys(final HpkeTestSuite suite) throws Exception {
      final KeyPair pair = suite.generateKeyPair();
      pub = (HpkePublicKey) pair.getPublic();
      priv = (HpkePrivateKey) pair.getPrivate();
    }
  }

  private static Keys keys(final HpkeTestSuite suite) throws Exception {
    suite.assumeAvailable();
    return new Keys(suite);
  }

  private static void assertOpenFails(final Executable call) {
    final AEADBadTagException ex = assertThrows(AEADBadTagException.class, call);
    assertEquals(DECRYPTION_FAILED, ex.getMessage());
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void roundTrip(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    assertEquals(suite.encLength, k.pub.encapsulationLength());
    assertEquals(suite.encLength, k.priv.encapsulationLength());
    for (final int len : new int[] {0, 1, 16, 4097}) {
      final byte[] pt = TestUtil.arrayOf((byte) 0x5a, len);
      final byte[] sealed = HpkeUtils.seal(k.pub, INFO, AAD, pt);
      assertEquals(suite.encLength + len + HpkeTestSuite.AEAD_OVERHEAD, sealed.length);
      assertArrayEquals(pt, HpkeUtils.open(k.priv, INFO, AAD, sealed));
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void freshEncapsulationPerCall(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final byte[] a = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    final byte[] b = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    assertFalse(Arrays.equals(a, b));
    assertArrayEquals(PLAINTEXT, HpkeUtils.open(k.priv, INFO, AAD, a));
    assertArrayEquals(PLAINTEXT, HpkeUtils.open(k.priv, INFO, AAD, b));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void nullInfoAndAadMeanEmpty(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final byte[] empty = new byte[0];
    assertArrayEquals(
        PLAINTEXT,
        HpkeUtils.open(k.priv, empty, empty, HpkeUtils.seal(k.pub, null, null, PLAINTEXT)));
    assertArrayEquals(
        PLAINTEXT,
        HpkeUtils.open(k.priv, null, null, HpkeUtils.seal(k.pub, empty, empty, PLAINTEXT)));
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    final byte[] sealed = HpkeUtils.seal(k.pub, null, null, PLAINTEXT);
    recipient.init(
        Cipher.DECRYPT_MODE,
        k.priv,
        k.priv.parameterSpec().withEncapsulation(Arrays.copyOf(sealed, suite.encLength)));
    assertArrayEquals(
        PLAINTEXT, recipient.doFinal(sealed, suite.encLength, sealed.length - suite.encLength));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void truncatedInputFailsUniformly(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final byte[] sealed = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    final int enc = suite.encLength;
    for (final int len : new int[] {0, enc - 1, enc, enc + 15, sealed.length - 1}) {
      final byte[] truncated = Arrays.copyOf(sealed, len);
      assertOpenFails(() -> HpkeUtils.open(k.priv, INFO, AAD, truncated));
    }
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void tamperedInputFailsUniformly(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final byte[] sealed = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    final int enc = suite.encLength;
    // A byte of enc (ML-KEM's implicit rejection makes it fail at the AEAD), of the ciphertext
    // body, and of the tag.
    for (final int index : new int[] {0, enc - 1, enc, sealed.length - 1}) {
      final byte[] tampered = sealed.clone();
      tampered[index] ^= 1;
      assertOpenFails(() -> HpkeUtils.open(k.priv, INFO, AAD, tampered));
    }
    final byte[] extended = Arrays.copyOf(sealed, sealed.length + 1);
    assertOpenFails(() -> HpkeUtils.open(k.priv, INFO, AAD, extended));
    assertOpenFails(() -> HpkeUtils.open(k.priv, new byte[] {9}, AAD, sealed));
    assertOpenFails(() -> HpkeUtils.open(k.priv, INFO, null, sealed));
    final HpkePrivateKey other = new Keys(suite).priv;
    assertOpenFails(() -> HpkeUtils.open(other, INFO, AAD, sealed));
    assertArrayEquals(PLAINTEXT, HpkeUtils.open(k.priv, INFO, AAD, sealed));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void sealOpensWithCipher(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final byte[] sealed = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    final int enc = k.priv.encapsulationLength();
    final Cipher recipient = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    recipient.init(
        Cipher.DECRYPT_MODE,
        k.priv,
        HpkeParameterSpec.of(suite.kemId, suite.kdfId, suite.aeadId)
            .withInfo(INFO)
            .withEncapsulation(Arrays.copyOf(sealed, enc)));
    recipient.updateAAD(AAD);
    assertArrayEquals(PLAINTEXT, recipient.doFinal(Arrays.copyOfRange(sealed, enc, sealed.length)));
  }

  @ParameterizedTest
  @EnumSource(HpkeTestSuite.class)
  public void cipherOpensWithOpen(final HpkeTestSuite suite) throws Exception {
    final Keys k = keys(suite);
    final Cipher sender = Cipher.getInstance("HPKE", NATIVE_PROVIDER);
    sender.init(Cipher.ENCRYPT_MODE, k.pub, k.pub.parameterSpec().withInfo(INFO));
    final byte[] enc = sender.getIV();
    sender.updateAAD(AAD);
    final byte[] ct = sender.doFinal(PLAINTEXT);
    final byte[] framed = Arrays.copyOf(enc, enc.length + ct.length);
    System.arraycopy(ct, 0, framed, enc.length, ct.length);
    assertArrayEquals(PLAINTEXT, HpkeUtils.open(k.priv, INFO, AAD, framed));
  }

  @Test
  public void rejectsNulls() throws Exception {
    final HpkeTestSuite suite = HpkeTestSuite.MLKEM768;
    final Keys k = keys(suite);
    assertThrows(IllegalArgumentException.class, () -> HpkeUtils.seal(null, INFO, AAD, PLAINTEXT));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtils.seal(k.pub, INFO, AAD, null));
    final byte[] sealed = HpkeUtils.seal(k.pub, INFO, AAD, PLAINTEXT);
    assertThrows(IllegalArgumentException.class, () -> HpkeUtils.open(null, INFO, AAD, sealed));
    assertThrows(IllegalArgumentException.class, () -> HpkeUtils.open(k.priv, INFO, AAD, null));
  }
}
