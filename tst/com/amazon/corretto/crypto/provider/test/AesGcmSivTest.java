// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for AES-GCM-SIV (RFC 8452) in ACCP.
 *
 * <p>Known-answer test vectors are sourced from RFC 8452 Appendix C.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public final class AesGcmSivTest {
  private static final String ALGO = "AES/GCM-SIV/NoPadding";

  private static byte[] h(final String hex) {
    try {
      return Hex.decodeHex(hex.toCharArray());
    } catch (DecoderException e) {
      throw new IllegalArgumentException("Invalid hex: " + hex, e);
    }
  }

  // Shared key / nonce for the C.1 and C.2 simple test cases.
  private static final String K128 = "01000000000000000000000000000000";
  private static final String K256 =
      "0100000000000000000000000000000000000000000000000000000000000000";
  private static final String N = "030000000000000000000000";

  // -----------------------------------------------------------------------
  // RFC 8452 Appendix C.1 – AEAD_AES_128_GCM_SIV
  // -----------------------------------------------------------------------

  // C.1, test 1: empty PT, empty AAD
  private static final String CT128_1 = "dc20e2d83f25705bb49e439eca56de25";

  // C.1, test 2: 8-byte PT, empty AAD
  private static final String PT128_2 = "0100000000000000";
  private static final String CT128_2 = "b5d839330ac7b786578782fff6013b815b287c22493a364c";

  // C.1, test 3: 12-byte PT, empty AAD
  private static final String PT128_3 = "010000000000000000000000";
  private static final String CT128_3 = "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639";

  // C.1, test 4: 16-byte PT, empty AAD
  private static final String PT128_4 = "01000000000000000000000000000000";
  private static final String CT128_4 =
      "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4";

  // C.1, test 5: 32-byte PT, empty AAD
  private static final String PT128_5 =
      "0100000000000000000000000000000002000000000000000000000000000000";
  private static final String CT128_5 =
      "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff";

  // C.1, test 8: 8-byte PT, 1-byte AAD
  private static final String PT128_8 = "0200000000000000";
  private static final String AAD128_8 = "01";
  private static final String CT128_8 = "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508";

  // C.1, test 14: 4-byte PT, 12-byte AAD
  private static final String PT128_14 = "02000000";
  private static final String AAD128_14 = "010000000000000000000000";
  private static final String CT128_14 = "a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14";

  // -----------------------------------------------------------------------
  // RFC 8452 Appendix C.2 – AEAD_AES_256_GCM_SIV
  // -----------------------------------------------------------------------

  // C.2, test 1: empty PT, empty AAD
  private static final String CT256_1 = "07f5f4169bbf55a8400cd47ea6fd400f";

  // C.2, test 2: 8-byte PT, empty AAD
  private static final String PT256_2 = "0100000000000000";
  private static final String CT256_2 = "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28";

  // C.2, test 3: 12-byte PT, empty AAD
  private static final String PT256_3 = "010000000000000000000000";
  private static final String CT256_3 = "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e";

  // C.2, test 4: 16-byte PT, empty AAD
  private static final String PT256_4 = "01000000000000000000000000000000";
  private static final String CT256_4 =
      "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366";

  // C.2, test 5: 32-byte PT, empty AAD
  private static final String PT256_5 =
      "0100000000000000000000000000000002000000000000000000000000000000";
  private static final String CT256_5 =
      "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d";

  // C.2, test 8: 8-byte PT, 1-byte AAD
  private static final String PT256_8 = "0200000000000000";
  private static final String AAD256_8 = "01";
  private static final String CT256_8 = "1de22967237a813291213f267e3b452f02d01ae33e4ec854";

  // C.2, test 14: 4-byte PT, 12-byte AAD
  private static final String PT256_14 = "02000000";
  private static final String AAD256_14 = "010000000000000000000000";
  private static final String CT256_14 = "22b3f4cd1835e517741dfddccfa07fa4661b74cf";

  // -----------------------------------------------------------------------
  // Test vector source
  // -----------------------------------------------------------------------

  static Stream<Arguments> rfcVectors() {
    return Stream.of(
        // AES-128
        Arguments.of("128-C1.1-empty-pt-empty-aad", K128, N, "", "", CT128_1),
        Arguments.of("128-C1.2-8pt-0aad", K128, N, PT128_2, "", CT128_2),
        Arguments.of("128-C1.3-12pt-0aad", K128, N, PT128_3, "", CT128_3),
        Arguments.of("128-C1.4-16pt-0aad", K128, N, PT128_4, "", CT128_4),
        Arguments.of("128-C1.5-32pt-0aad", K128, N, PT128_5, "", CT128_5),
        Arguments.of("128-C1.8-8pt-1aad", K128, N, PT128_8, AAD128_8, CT128_8),
        Arguments.of("128-C1.14-4pt-12aad", K128, N, PT128_14, AAD128_14, CT128_14),
        // AES-256
        Arguments.of("256-C2.1-empty-pt-empty-aad", K256, N, "", "", CT256_1),
        Arguments.of("256-C2.2-8pt-0aad", K256, N, PT256_2, "", CT256_2),
        Arguments.of("256-C2.3-12pt-0aad", K256, N, PT256_3, "", CT256_3),
        Arguments.of("256-C2.4-16pt-0aad", K256, N, PT256_4, "", CT256_4),
        Arguments.of("256-C2.5-32pt-0aad", K256, N, PT256_5, "", CT256_5),
        Arguments.of("256-C2.8-8pt-1aad", K256, N, PT256_8, AAD256_8, CT256_8),
        Arguments.of("256-C2.14-4pt-12aad", K256, N, PT256_14, AAD256_14, CT256_14));
  }

  // -----------------------------------------------------------------------
  // KAT: encrypt
  // -----------------------------------------------------------------------

  @ParameterizedTest(name = "encrypt-{0}")
  @MethodSource("rfcVectors")
  public void rfcEncrypt(
      final String name,
      final String keyHex,
      final String nonceHex,
      final String ptHex,
      final String aadHex,
      final String ctHex)
      throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(h(keyHex), "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, h(nonceHex));
    final byte[] plaintext = ptHex.isEmpty() ? new byte[0] : h(ptHex);
    final byte[] aad = aadHex.isEmpty() ? null : h(aadHex);
    final byte[] expectedCt = h(ctHex);

    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    if (aad != null) {
      cipher.updateAAD(aad);
    }
    final byte[] ct = cipher.doFinal(plaintext);
    assertArraysHexEquals(expectedCt, ct);
  }

  // -----------------------------------------------------------------------
  // KAT: decrypt
  // -----------------------------------------------------------------------

  @ParameterizedTest(name = "decrypt-{0}")
  @MethodSource("rfcVectors")
  public void rfcDecrypt(
      final String name,
      final String keyHex,
      final String nonceHex,
      final String ptHex,
      final String aadHex,
      final String ctHex)
      throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(h(keyHex), "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, h(nonceHex));
    final byte[] expectedPt = ptHex.isEmpty() ? new byte[0] : h(ptHex);
    final byte[] aad = aadHex.isEmpty() ? null : h(aadHex);
    final byte[] ct = h(ctHex);

    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.DECRYPT_MODE, key, spec);
    if (aad != null) {
      cipher.updateAAD(aad);
    }
    final byte[] pt = cipher.doFinal(ct);
    assertArraysHexEquals(expectedPt, pt);
  }

  // -----------------------------------------------------------------------
  // Round-trip: basic sanity check with real data
  // -----------------------------------------------------------------------

  @Test
  public void roundTripAes128() throws GeneralSecurityException {
    roundTrip(new byte[16]);
  }

  @Test
  public void roundTripAes256() throws GeneralSecurityException {
    roundTrip(new byte[32]);
  }

  private void roundTrip(final byte[] rawKey) throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(rawKey, "AES");
    final byte[] nonce = new byte[12];
    final byte[] plaintext = "Hello, AES-GCM-SIV!".getBytes();
    final byte[] aad = "additional data".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    enc.updateAAD(aad);
    final byte[] ct = enc.doFinal(plaintext);

    assertEquals(plaintext.length + 16, ct.length);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    dec.updateAAD(aad);
    final byte[] recovered = dec.doFinal(ct);

    assertArrayEquals(plaintext, recovered);
  }

  // -----------------------------------------------------------------------
  // Streaming: update calls should buffer; doFinal produces output
  // -----------------------------------------------------------------------

  @Test
  public void streamingEncryptMatchesOneShot() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = new byte[64];
    for (int i = 0; i < plaintext.length; i++) {
      plaintext[i] = (byte) i;
    }

    // One-shot
    final Cipher oneShot = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    oneShot.init(Cipher.ENCRYPT_MODE, key, spec);
    final byte[] oneShotCt = oneShot.doFinal(plaintext);

    // Streaming: feed in 16 bytes at a time
    final Cipher streaming = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    streaming.init(Cipher.ENCRYPT_MODE, key, spec);
    for (int i = 0; i < plaintext.length; i += 16) {
      final byte[] chunk = streaming.update(plaintext, i, 16);
      assertEquals(0, chunk.length, "update() should return empty array for AES-GCM-SIV");
    }
    final byte[] streamingCt = streaming.doFinal();

    assertArrayEquals(oneShotCt, streamingCt);
  }

  // -----------------------------------------------------------------------
  // Authentication failure detection
  // -----------------------------------------------------------------------

  @Test
  public void badTagThrowsAEADBadTagException() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "test".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    final byte[] ct = enc.doFinal(plaintext);

    // Corrupt the last byte of the tag
    ct[ct.length - 1] ^= 0xFF;

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct));
  }

  @Test
  public void wrongAadThrowsAEADBadTagException() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "test".getBytes();
    final byte[] aad = "correct aad".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    enc.updateAAD(aad);
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    dec.updateAAD("wrong aad".getBytes());
    assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct));
  }

  // -----------------------------------------------------------------------
  // Parameter validation
  // -----------------------------------------------------------------------

  @Test
  public void rejectsNon12ByteNonce() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[16])));
  }

  @Test
  public void rejectsNon128BitTag() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(96, new byte[12])));
  }

  @Test
  public void rejects192BitKey() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[24], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12])));
  }

  @Test
  public void rejectsIvParameterSpec() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[12])));
  }

  // -----------------------------------------------------------------------
  // Nonce reuse: GCM-SIV tolerates key+nonce reuse (no exception thrown)
  // -----------------------------------------------------------------------

  @Test
  public void nonceReuseDoesNotThrow() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    enc.doFinal("first message".getBytes());

    // Re-init with same key+nonce must NOT throw for AES-GCM-SIV
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    enc.doFinal("second message".getBytes());
  }

  // -----------------------------------------------------------------------
  // Algorithm name variants
  // -----------------------------------------------------------------------

  @Test
  public void aes128AlgoNameVariant() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance("AES_128/GCM-SIV/NoPadding", NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    assertNotNull(cipher.doFinal(new byte[8]));
  }

  @Test
  public void aes256AlgoNameVariant() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[32], "AES");
    final Cipher cipher = Cipher.getInstance("AES_256/GCM-SIV/NoPadding", NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    assertNotNull(cipher.doFinal(new byte[8]));
  }
}
