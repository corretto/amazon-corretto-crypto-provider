// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
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
  // RFC 8452 Appendix C.1 - AEAD_AES_128_GCM_SIV
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
  // RFC 8452 Appendix C.2 - AEAD_AES_256_GCM_SIV
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
  public void acceptsIvParameterSpec() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final byte[] plaintext = "iv param spec".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[12]));
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[12]));
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  @Test
  public void rejectsIvParameterSpecWrongLength() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16])));
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

  // -----------------------------------------------------------------------
  // ByteBuffer: encrypt and decrypt via NIO buffers
  // -----------------------------------------------------------------------

  @Test
  public void byteBufferEncryptDecrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "ByteBuffer test data".getBytes();

    // Encrypt using ByteBuffers
    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    final ByteBuffer ptBuf = ByteBuffer.wrap(plaintext);
    final ByteBuffer ctBuf = ByteBuffer.allocate(enc.getOutputSize(plaintext.length));
    enc.doFinal(ptBuf, ctBuf);
    ctBuf.flip();
    final byte[] ciphertext = new byte[ctBuf.remaining()];
    ctBuf.get(ciphertext);

    assertEquals(plaintext.length + 16, ciphertext.length);

    // Decrypt using ByteBuffers
    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    final ByteBuffer ctIn = ByteBuffer.wrap(ciphertext);
    final ByteBuffer ptOut = ByteBuffer.allocate(dec.getOutputSize(ciphertext.length));
    dec.doFinal(ctIn, ptOut);
    ptOut.flip();
    final byte[] recovered = new byte[ptOut.remaining()];
    ptOut.get(recovered);

    assertArrayEquals(plaintext, recovered);
  }

  @Test
  public void byteBufferDirectEncryptDecrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[32], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = new byte[256];
    ThreadLocalRandom.current().nextBytes(plaintext);

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    final ByteBuffer ptBuf = ByteBuffer.allocateDirect(plaintext.length);
    ptBuf.put(plaintext).flip();
    final ByteBuffer ctBuf = ByteBuffer.allocateDirect(enc.getOutputSize(plaintext.length));
    enc.doFinal(ptBuf, ctBuf);
    ctBuf.flip();

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    final ByteBuffer ptOut = ByteBuffer.allocateDirect(dec.getOutputSize(ctBuf.remaining()));
    dec.doFinal(ctBuf, ptOut);
    ptOut.flip();
    final byte[] recovered = new byte[ptOut.remaining()];
    ptOut.get(recovered);

    assertArrayEquals(plaintext, recovered);
  }

  // -----------------------------------------------------------------------
  // getOutputSize: must be exact for encrypt (pt + 16) and decrypt (ct - 16)
  // -----------------------------------------------------------------------

  @Test
  public void getOutputSizeEncrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    for (final int ptLen : new int[] {0, 1, 15, 16, 17, 100, 1024}) {
      assertEquals(ptLen + 16, cipher.getOutputSize(ptLen), "ptLen=" + ptLen);
    }
  }

  @Test
  public void getOutputSizeDecrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    for (final int ctLen : new int[] {16, 17, 32, 100, 1024}) {
      assertEquals(ctLen - 16, cipher.getOutputSize(ctLen), "ctLen=" + ctLen);
    }
  }

  // -----------------------------------------------------------------------
  // Large input (~1 MiB): verify correctness at scale
  // -----------------------------------------------------------------------

  @Test
  public void largePlaintextRoundTrip() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = new byte[1024 * 1024];
    ThreadLocalRandom.current().nextBytes(plaintext);

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    final byte[] ct = enc.doFinal(plaintext);
    assertEquals(plaintext.length + 16, ct.length);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    final byte[] recovered = dec.doFinal(ct);
    assertArrayEquals(plaintext, recovered);
  }

  // -----------------------------------------------------------------------
  // Rekey: reinit with a different key on the same Cipher instance
  // -----------------------------------------------------------------------

  @Test
  public void rekeyChangesOutput() throws GeneralSecurityException {
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "rekey test".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);

    enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), spec);
    final byte[] ct1 = enc.doFinal(plaintext);

    // Different key - ciphertext must differ
    final byte[] rawKey2 = new byte[16];
    rawKey2[0] = 1;
    enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey2, "AES"), spec);
    final byte[] ct2 = enc.doFinal(plaintext);

    assertEquals(ct1.length, ct2.length);
    // The two ciphertexts must not be equal (overwhelmingly likely with different keys)
    boolean differ = false;
    for (int i = 0; i < ct1.length; i++) {
      if (ct1[i] != ct2[i]) {
        differ = true;
        break;
      }
    }
    assertEquals(true, differ, "Different keys must produce different ciphertexts");
  }

  // -----------------------------------------------------------------------
  // AAD after update: must throw IllegalStateException
  // -----------------------------------------------------------------------

  @Test
  public void aadAfterUpdateThrows() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    cipher.update(new byte[8]);
    assertThrows(IllegalStateException.class, () -> cipher.updateAAD(new byte[4]));
  }

  // -----------------------------------------------------------------------
  // Threading: many concurrent encrypt+decrypt pairs on distinct Cipher instances
  // -----------------------------------------------------------------------

  @Test
  public void concurrentEncryptDecrypt() throws Exception {
    final int threadCount = 16;
    final int iterations = 50;
    final SecretKey key128 = new SecretKeySpec(new byte[16], "AES");
    final SecretKey key256 = new SecretKeySpec(new byte[32], "AES");
    final SecretKey[] keys = {key128, key256};

    final List<Thread> threads = new ArrayList<>();
    final List<Throwable> failures = new ArrayList<>();

    for (int t = 0; t < threadCount; t++) {
      final int threadIdx = t;
      final Thread thread =
          new Thread(
              () -> {
                try {
                  final SecureRandom rng = new SecureRandom();
                  final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
                  final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
                  for (int i = 0; i < iterations; i++) {
                    final SecretKey key = keys[(threadIdx + i) % keys.length];
                    final byte[] nonce = new byte[12];
                    rng.nextBytes(nonce);
                    final GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
                    final byte[] plaintext = new byte[64 + (i % 64)];
                    rng.nextBytes(plaintext);

                    enc.init(Cipher.ENCRYPT_MODE, key, spec);
                    final byte[] ct = enc.doFinal(plaintext);

                    dec.init(Cipher.DECRYPT_MODE, key, spec);
                    final byte[] recovered = dec.doFinal(ct);
                    assertArrayEquals(plaintext, recovered);
                  }
                } catch (final Throwable ex) {
                  synchronized (failures) {
                    failures.add(ex);
                  }
                }
              },
              "gcm-siv-thread-" + t);
      threads.add(thread);
    }

    for (final Thread thread : threads) {
      thread.start();
    }
    for (final Thread thread : threads) {
      thread.join();
    }

    if (!failures.isEmpty()) {
      final AssertionError error = new AssertionError("Thread failures: " + failures.size());
      failures.forEach(error::addSuppressed);
      throw error;
    }
  }

  // -----------------------------------------------------------------------
  // engineInit with random nonce (no AlgorithmParameterSpec)
  // -----------------------------------------------------------------------

  @Test
  public void encryptWithRandomNonce() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
    final byte[] nonce = enc.getIV();
    assertNotNull(nonce);
    assertEquals(12, nonce.length);

    final byte[] plaintext = "random nonce test".getBytes();
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  @Test
  public void decryptWithoutNonceThrows() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertThrows(
        InvalidKeyException.class, () -> cipher.init(Cipher.DECRYPT_MODE, key, new SecureRandom()));
  }

  // -----------------------------------------------------------------------
  // engineInit with AlgorithmParameters
  // -----------------------------------------------------------------------

  @Test
  public void initWithAlgorithmParameters() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final byte[] nonce = new byte[12];

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    final AlgorithmParameters params = enc.getParameters();
    assertNotNull(params);

    final byte[] plaintext = "algo params test".getBytes();
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, params);
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  // -----------------------------------------------------------------------
  // engineGetIV: null before init, 12 bytes after
  // -----------------------------------------------------------------------

  @Test
  public void getIvBeforeInit() throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertNull(cipher.getIV());
  }

  @Test
  public void getIvAfterInit() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final byte[] nonce = new byte[12];
    nonce[0] = 42;
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    assertArrayEquals(nonce, cipher.getIV());
  }

  // -----------------------------------------------------------------------
  // engineGetParameters: generates a fresh nonce when uninitialized
  // -----------------------------------------------------------------------

  @Test
  public void getParametersBeforeInit() throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    final AlgorithmParameters params = cipher.getParameters();
    assertNotNull(params);
    final GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
    assertEquals(12, spec.getIV().length);
    assertEquals(128, spec.getTLen());
  }

  // -----------------------------------------------------------------------
  // engineGetBlockSize
  // -----------------------------------------------------------------------

  @Test
  public void getBlockSize() throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    assertEquals(16, cipher.getBlockSize());
  }

  // -----------------------------------------------------------------------
  // engineUpdateAAD(ByteBuffer): array-backed and direct
  // -----------------------------------------------------------------------

  @Test
  public void updateAadByteBufferArrayBacked() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "aad bytebuffer".getBytes();
    final byte[] aad = "associated".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    enc.updateAAD(ByteBuffer.wrap(aad));
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    dec.updateAAD(ByteBuffer.wrap(aad));
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  @Test
  public void updateAadByteBufferDirect() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
    final byte[] plaintext = "aad direct buffer".getBytes();
    final byte[] aad = "direct aad".getBytes();

    final ByteBuffer aadBuf = ByteBuffer.allocateDirect(aad.length);
    aadBuf.put(aad).flip();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.ENCRYPT_MODE, key, spec);
    enc.updateAAD(aadBuf.duplicate());
    final byte[] ct = enc.doFinal(plaintext);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, spec);
    dec.updateAAD(aadBuf.duplicate());
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  // -----------------------------------------------------------------------
  // Wrap / Unwrap
  // -----------------------------------------------------------------------

  @Test
  public void wrapAndUnwrap() throws GeneralSecurityException {
    final SecretKey wrappingKey = new SecretKeySpec(new byte[16], "AES");
    final SecretKey keyToWrap = new SecretKeySpec(new byte[32], "AES");
    final GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    enc.init(Cipher.WRAP_MODE, wrappingKey, spec);
    final byte[] wrapped = enc.wrap(keyToWrap);

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.UNWRAP_MODE, wrappingKey, spec);
    final SecretKey recovered = (SecretKey) dec.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

    assertArrayEquals(keyToWrap.getEncoded(), recovered.getEncoded());
  }

  // -----------------------------------------------------------------------
  // Decrypt with ciphertext shorter than the 16-byte tag
  // -----------------------------------------------------------------------

  @Test
  public void decryptTooShortThrows() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    assertThrows(AEADBadTagException.class, () -> dec.doFinal(new byte[8]));
  }

  // -----------------------------------------------------------------------
  // Same-key context caching: exercises the cached-context path in nSeal/nOpen
  // -----------------------------------------------------------------------

  @Test
  public void sameKeyContextCachingEncrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final byte[] plaintext = "cache test".getBytes();

    final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);

    // First call: new key, no cached context
    enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
    enc.doFinal(plaintext);

    // Second call: same key bytes, context gets saved (sameKey=true -> saveNativeContext=true)
    final byte[] nonce2 = new byte[12];
    nonce2[0] = 1;
    enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce2));
    enc.doFinal(plaintext);

    // Third call: context != null, uses cached context
    final byte[] nonce3 = new byte[12];
    nonce3[0] = 2;
    enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce3));
    final byte[] ct = enc.doFinal(plaintext);

    // Verify correctness via decrypt
    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce3));
    assertArrayEquals(plaintext, dec.doFinal(ct));
  }

  @Test
  public void sameKeyContextCachingDecrypt() throws GeneralSecurityException {
    final SecretKey key = new SecretKeySpec(new byte[16], "AES");
    final byte[] plaintext = "cache decrypt test".getBytes();

    // Pre-encrypt three ciphertexts with distinct nonces
    final byte[][] nonces = {new byte[12], new byte[12], new byte[12]};
    nonces[1][0] = 1;
    nonces[2][0] = 2;
    final byte[][] cts = new byte[3][];
    for (int i = 0; i < 3; i++) {
      final Cipher enc = Cipher.getInstance(ALGO, NATIVE_PROVIDER);
      enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonces[i]));
      cts[i] = enc.doFinal(plaintext);
    }

    final Cipher dec = Cipher.getInstance(ALGO, NATIVE_PROVIDER);

    // First decrypt: no cached context
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonces[0]));
    dec.doFinal(cts[0]);

    // Second decrypt: sameKey=true, context saved
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonces[1]));
    dec.doFinal(cts[1]);

    // Third decrypt: context != null, uses cached context
    dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonces[2]));
    assertArrayEquals(plaintext, dec.doFinal(cts[2]));
  }
}
