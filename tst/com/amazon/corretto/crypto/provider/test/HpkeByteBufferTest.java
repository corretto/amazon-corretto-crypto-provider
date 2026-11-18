// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.HpkeTestSuite.cipher;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Exercises the default CipherSpi path across its 4096-byte direct/read-only buffer chunks. One
 * suite suffices because buffer handling is suite-independent.
 */
@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class HpkeByteBufferTest {
  private static final HpkeTestSuite SUITE = HpkeTestSuite.MLKEM768;
  private static final int[] SIZES = {0, 1, 4095, 4096, 4097, 1 << 20};

  enum InputKind {
    HEAP,
    DIRECT,
    HEAP_READ_ONLY,
    DIRECT_READ_ONLY
  }

  enum OutputKind {
    HEAP,
    DIRECT
  }

  private static byte[] randomBytes(final int len) {
    final byte[] result = new byte[len];
    new Random(len).nextBytes(result);
    return result;
  }

  private static ByteBuffer input(final InputKind kind, final byte[] data) {
    final boolean direct = kind == InputKind.DIRECT || kind == InputKind.DIRECT_READ_ONLY;
    final ByteBuffer buf =
        direct ? ByteBuffer.allocateDirect(data.length) : ByteBuffer.allocate(data.length);
    buf.put(data);
    buf.flip();
    if (kind == InputKind.HEAP_READ_ONLY || kind == InputKind.DIRECT_READ_ONLY) {
      return buf.asReadOnlyBuffer();
    }
    return buf;
  }

  private static ByteBuffer output(final OutputKind kind, final int capacity) {
    return kind == OutputKind.DIRECT
        ? ByteBuffer.allocateDirect(capacity)
        : ByteBuffer.allocate(capacity);
  }

  private static byte[] written(final ByteBuffer buf) {
    final ByteBuffer view = buf.duplicate();
    view.flip();
    final byte[] result = new byte[view.remaining()];
    view.get(result);
    return result;
  }

  private static byte[] open(final KeyPair kp, final byte[] enc, final byte[] ct) throws Exception {
    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), SUITE.spec().withEncapsulation(enc));
    return recipient.doFinal(ct);
  }

  static List<Arguments> bufferCases() {
    final List<Arguments> result = new ArrayList<>();
    for (final int size : SIZES) {
      for (final InputKind in : InputKind.values()) {
        for (final OutputKind out : OutputKind.values()) {
          result.add(Arguments.of(size, in, out));
        }
      }
    }
    return result;
  }

  @ParameterizedTest(name = "size={0} in={1} out={2}")
  @MethodSource("bufferCases")
  public void doFinalRoundTrip(final int size, final InputKind inKind, final OutputKind outKind)
      throws Exception {
    SUITE.assumeAvailable();
    final KeyPair kp = SUITE.generateKeyPair();
    final byte[] plaintext = randomBytes(size);
    final int ctLen = size + HpkeTestSuite.AEAD_OVERHEAD;

    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), SUITE.spec());
    final ByteBuffer ptIn = input(inKind, plaintext);
    final ByteBuffer ctOut = output(outKind, ctLen);
    assertEquals(ctLen, sender.doFinal(ptIn, ctOut));
    assertEquals(size, ptIn.position());
    assertEquals(ctLen, ctOut.position());
    final byte[] enc = sender.getIV();
    assertEquals(SUITE.encLength, enc.length);
    final byte[] ct = written(ctOut);

    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), SUITE.spec().withEncapsulation(enc));
    final ByteBuffer ctIn = input(inKind, ct);
    final ByteBuffer ptOut = output(outKind, size);
    assertEquals(size, recipient.doFinal(ctIn, ptOut));
    assertEquals(ctLen, ctIn.position());
    assertEquals(size, ptOut.position());
    assertArrayEquals(plaintext, written(ptOut));
  }

  @ParameterizedTest(name = "size={0}")
  @ValueSource(ints = {4097, 1 << 20})
  public void updateThenDoFinal(final int size) throws Exception {
    SUITE.assumeAvailable();
    final KeyPair kp = SUITE.generateKeyPair();
    final byte[] plaintext = randomBytes(size);
    final int ctLen = size + HpkeTestSuite.AEAD_OVERHEAD;

    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), SUITE.spec());
    final ByteBuffer ptIn = input(InputKind.DIRECT, plaintext);
    final ByteBuffer ctOut = output(OutputKind.DIRECT, ctLen);
    assertEquals(0, sender.update(ptIn, ctOut));
    assertEquals(0, ctOut.position());
    assertEquals(ctLen, sender.doFinal(ptIn, ctOut));
    final byte[] enc = sender.getIV();
    final byte[] ct = written(ctOut);
    assertEquals(ctLen, ct.length);

    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), SUITE.spec().withEncapsulation(enc));
    final ByteBuffer ctIn = input(InputKind.DIRECT, ct);
    final ByteBuffer ptOut = output(OutputKind.DIRECT, size);
    assertEquals(0, recipient.update(ctIn, ptOut));
    assertEquals(0, ptOut.position());
    assertEquals(size, recipient.doFinal(ctIn, ptOut));
    assertArrayEquals(plaintext, written(ptOut));
  }

  @ParameterizedTest(name = "direct={0}")
  @ValueSource(booleans = {false, true})
  public void inPlace(final boolean direct) throws Exception {
    SUITE.assumeAvailable();
    final KeyPair kp = SUITE.generateKeyPair();
    final int size = 4097;
    final byte[] plaintext = randomBytes(size);
    final int ctLen = size + HpkeTestSuite.AEAD_OVERHEAD;
    final ByteBuffer backing =
        direct ? ByteBuffer.allocateDirect(ctLen) : ByteBuffer.allocate(ctLen);
    backing.put(plaintext);

    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), SUITE.spec());
    ByteBuffer in = backing.duplicate();
    in.clear();
    in.limit(size);
    ByteBuffer out = backing.duplicate();
    out.clear();
    assertEquals(ctLen, sender.doFinal(in, out));
    final byte[] enc = sender.getIV();
    final byte[] ct = written(out);

    final Cipher recipient = cipher();
    recipient.init(Cipher.DECRYPT_MODE, kp.getPrivate(), SUITE.spec().withEncapsulation(enc));
    in = backing.duplicate();
    in.clear();
    out = backing.duplicate();
    out.clear();
    assertEquals(size, recipient.doFinal(in, out));
    assertArrayEquals(plaintext, written(out));
    assertArrayEquals(plaintext, open(kp, enc, ct));
  }

  @ParameterizedTest(name = "direct={0}")
  @ValueSource(booleans = {false, true})
  public void shortOutputThenRetry(final boolean direct) throws Exception {
    SUITE.assumeAvailable();
    final KeyPair kp = SUITE.generateKeyPair();
    final int size = 4097;
    final byte[] plaintext = randomBytes(size);
    final int ctLen = size + HpkeTestSuite.AEAD_OVERHEAD;
    final InputKind inKind = direct ? InputKind.DIRECT : InputKind.HEAP;
    final OutputKind outKind = direct ? OutputKind.DIRECT : OutputKind.HEAP;

    final Cipher sender = cipher();
    sender.init(Cipher.ENCRYPT_MODE, kp.getPublic(), SUITE.spec());
    final ByteBuffer ptIn = input(inKind, plaintext);
    final ByteBuffer tooSmall = output(outKind, ctLen - 1);
    assertThrows(ShortBufferException.class, () -> sender.doFinal(ptIn, tooSmall));
    assertEquals(0, ptIn.position());
    assertEquals(0, tooSmall.position());

    final ByteBuffer ctOut = output(outKind, ctLen);
    assertEquals(ctLen, sender.doFinal(ptIn, ctOut));
    final byte[] enc = sender.getIV();
    assertArrayEquals(plaintext, open(kp, enc, written(ctOut)));
  }
}
