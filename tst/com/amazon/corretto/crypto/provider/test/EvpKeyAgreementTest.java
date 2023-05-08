// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD) // Parameters are shared
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EvpKeyAgreementTest {
  private static final BouncyCastleProvider BC_PROV = new BouncyCastleProvider();
  private static final int PAIR_COUNT = 25;
  private static List<TestParams> MASTER_PARAMS_LIST;

  // Build the params list once to avoid recomputing it
  @BeforeAll
  public static void setupParams() throws GeneralSecurityException, IOException {
    MASTER_PARAMS_LIST = new ArrayList<>();
    MASTER_PARAMS_LIST.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-256"), "NIST P-256"));
    MASTER_PARAMS_LIST.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-384"), "NIST P-384"));
    MASTER_PARAMS_LIST.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-521"), "NIST P-521"));
    MASTER_PARAMS_LIST.add(buildEcdhParameters(EcGenTest.EXPLICIT_CURVE, "Explicit Curve"));
  }

  // No need to keep these in memory
  @AfterAll
  public static void cleanupParams() {
    MASTER_PARAMS_LIST = null;
  }

  public static List<TestParams> params() {
    return MASTER_PARAMS_LIST;
  }

  private static class TestParams {
    private final String algorithm;

    @SuppressWarnings("unused")
    private final String displayName;

    @SuppressWarnings("unused")
    private final KeyPairGenerator keyGen;
    // We test pairwise across lots of keypairs in an effort
    // to catch rarer edge-cases.
    private final KeyPair[] pairs;
    private final byte[][][] rawSecrets;
    private final List<? extends PublicKey> invalidKeys;
    private final Provider nativeProvider;
    private final Provider jceProvider;
    private KeyAgreement nativeAgreement;
    private KeyAgreement jceAgreement;

    public TestParams(
        final String algorithm,
        final String displayName,
        final KeyPairGenerator keyGen,
        final Provider nativeProvider,
        final Provider jceProvider,
        final List<? extends PublicKey> invalidKeys)
        throws GeneralSecurityException {
      this.algorithm = algorithm;
      this.displayName = displayName;
      this.keyGen = keyGen;
      this.invalidKeys = invalidKeys;
      this.nativeProvider = nativeProvider;
      this.jceProvider = jceProvider;

      nativeAgreement = KeyAgreement.getInstance(algorithm, nativeProvider);
      jceAgreement = KeyAgreement.getInstance(algorithm, jceProvider);

      pairs = new KeyPair[PAIR_COUNT];
      for (int x = 0; x < pairs.length; x++) {
        pairs[x] = keyGen.generateKeyPair();
      }

      // Do pairwise agreement between all pairs
      rawSecrets = new byte[pairs.length][][];
      for (int x = 0; x < pairs.length; x++) {
        rawSecrets[x] = new byte[pairs.length][];
      }
      for (int x = 0; x < pairs.length; x++) {
        for (int y = x; y < pairs.length; y++) {
          jceAgreement.init(pairs[x].getPrivate());
          jceAgreement.doPhase(pairs[y].getPublic(), true);
          rawSecrets[x][y] = jceAgreement.generateSecret();
          rawSecrets[y][x] = rawSecrets[x][y];
        }
      }
    }

    @Override
    public String toString() {
      return displayName;
    }
  }

  private static TestParams buildEcdhParameters(
      final AlgorithmParameterSpec genSpec, final String name)
      throws GeneralSecurityException, IOException {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    generator.initialize(genSpec);
    final KeyPair pair = generator.generateKeyPair();
    final ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
    return new TestParams(
        "ECDH",
        "ECDH(" + name + ")",
        generator,
        NATIVE_PROVIDER,
        BC_PROV,
        Arrays.asList(
            buildKeyAtInfinity(pubKey), buildKeyOffCurve(pubKey), buildKeyOnWrongCurve(pubKey)));
  }

  static ECPublicKey buildKeyOffCurve(final ECPublicKey goodKey) throws GeneralSecurityException {
    // // NOTE: we can't use NATIVE_PROVIDER to create an invalid key because it will error if
    //          the point is off the curve.
    final KeyFactory factory = KeyFactory.getInstance("EC");
    final ECPoint w =
        new ECPoint(goodKey.getW().getAffineX().add(BigInteger.ONE), goodKey.getW().getAffineY());
    final ECPublicKey badKey =
        (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(w, goodKey.getParams()));
    return badKey;
  }

  static ECPublicKey buildKeyAtInfinity(final ECPublicKey goodKey) throws IOException {
    // We can't build this normally because Java protects us from these bad keys
    final byte[] goodDer = goodKey.getEncoded();
    ASN1Sequence seq = ASN1Sequence.getInstance(goodDer);
    // This should consist of two elements, algorithm and the actual key
    assertEquals(2, seq.size(), "Unexpected ASN.1 encoding");
    // The key itself is just a byte encoding of the point
    DERBitString point =
        new DERBitString(new byte[1]); // a one byte zero array is the point at infinity
    seq = new DERSequence(new ASN1Encodable[] {seq.getObjectAt(0), point});
    return new FakeEcPublicKey(seq.getEncoded("DER"), goodKey.getParams(), ECPoint.POINT_INFINITY);
  }

  static ECPublicKey buildKeyOnWrongCurve(final ECPublicKey goodKey)
      throws GeneralSecurityException {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    final EllipticCurve curve = goodKey.getParams().getCurve();
    if (curve.getField() instanceof ECFieldFp) {
      // This is a prime curve
      generator.initialize(new ECGenParameterSpec("NIST P-384"));
      final ECPublicKey pub1 = (ECPublicKey) generator.generateKeyPair().getPublic();
      generator.initialize(new ECGenParameterSpec("NIST P-256"));
      final ECPublicKey pub2 = (ECPublicKey) generator.generateKeyPair().getPublic();

      if (curve.getField().getFieldSize()
          == pub1.getParams().getCurve().getField().getFieldSize()) {
        return pub2;
      } else {
        return pub1;
      }
    } else {
      generator.initialize(new ECGenParameterSpec("sect163k1"));
      final ECPublicKey pub1 = (ECPublicKey) generator.generateKeyPair().getPublic();
      generator.initialize(new ECGenParameterSpec("sect283k1"));
      final ECPublicKey pub2 = (ECPublicKey) generator.generateKeyPair().getPublic();

      if (curve.getField().getFieldSize()
          == pub1.getParams().getCurve().getField().getFieldSize()) {
        return pub2;
      } else {
        return pub1;
      }
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void jceCompatability(TestParams params) {
    assertForAllPairs(
        params,
        (pub, priv, expected) -> {
          params.nativeAgreement.init(priv);
          assertNull(params.nativeAgreement.doPhase(pub, true));
          assertArrayEquals(expected, params.nativeAgreement.generateSecret());
        });
  }

  @ParameterizedTest
  @MethodSource("params")
  public void tlsMasterSecret(TestParams params) {
    // For TLS suppport we /must/ support this algorithm
    assertForAllPairs(
        params,
        (pub, priv, ignored) -> {
          params.nativeAgreement.init(priv);
          assertNull(params.nativeAgreement.doPhase(pub, true));
          final SecretKey nativeKey = params.nativeAgreement.generateSecret("TlsPremasterSecret");

          params.jceAgreement.init(priv);
          params.jceAgreement.doPhase(pub, true);
          final SecretKey jceKey = params.jceAgreement.generateSecret("TlsPremasterSecret");

          assertEquals(jceKey.getAlgorithm(), nativeKey.getAlgorithm());
          assertEquals(jceKey.getFormat(), nativeKey.getFormat());
          assertArrayEquals(jceKey.getEncoded(), nativeKey.getEncoded());
        });
  }

  private static Stream<TestParams> aesKeysParams() {
    return params().stream()
        .filter(
            p -> {
              final int expectedKeyLength = Math.min(32, (p.rawSecrets[0][1].length / 8) * 8);
              return expectedKeyLength > 16;
            });
  }

  @ParameterizedTest
  @MethodSource("aesKeysParams")
  public void aesKeys(TestParams params) throws GeneralSecurityException {
    final byte[] rawSecret = params.rawSecrets[0][1];
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));

    final int expectedKeyLength = Math.min(32, (rawSecret.length / 8) * 8);
    final SecretKey aesKey = params.nativeAgreement.generateSecret("AES");
    assertEquals("AES", aesKey.getAlgorithm());
    assertEquals("RAW", aesKey.getFormat());
    assertArrayEquals(Arrays.copyOf(rawSecret, expectedKeyLength), aesKey.getEncoded());
  }

  @ParameterizedTest
  @MethodSource("params")
  public void aesKeysExplicitSize(TestParams params) throws GeneralSecurityException {
    // 0, 20, and 4096 to trigger error cases
    final int[] keySizes = new int[] {0, 16, 20, 24, 32, 4096};
    for (final int size : keySizes) {
      final byte[] rawSecret = params.rawSecrets[0][1];
      params.nativeAgreement.init(params.pairs[0].getPrivate());
      assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
      final String secretAlg = "AES[" + size + "]";
      if (size > 0 && size <= rawSecret.length && size != 20) {
        final SecretKey aesKey = params.nativeAgreement.generateSecret(secretAlg);
        assertEquals("AES", aesKey.getAlgorithm());
        assertEquals("RAW", aesKey.getFormat());
        assertArrayEquals(Arrays.copyOf(rawSecret, size), aesKey.getEncoded());
      } else {
        assertThrows(
            InvalidKeyException.class, () -> params.nativeAgreement.generateSecret(secretAlg));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void fakeAlgorithm(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
    assertThrows(
        InvalidKeyException.class, () -> params.nativeAgreement.generateSecret("FAKE_ALG"));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void fakeAlgorithmExplicitSize(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
    assertThrows(
        InvalidKeyException.class, () -> params.nativeAgreement.generateSecret("FAKE_ALG[8]"));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void fakeWeirdAlgorithmName(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
    assertThrows(
        InvalidKeyException.class, () -> params.nativeAgreement.generateSecret(" #$*(& DO  3VR89"));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void secretInExistingArray(TestParams params) throws GeneralSecurityException {
    final byte[] rawSecret = params.rawSecrets[0][1];
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
    final byte[] largeArray = new byte[rawSecret.length + 3];
    params.nativeAgreement.generateSecret(largeArray, 1);

    assertArrayEquals(rawSecret, Arrays.copyOfRange(largeArray, 1, 1 + rawSecret.length));
    assertEquals(0, largeArray[0]);
    assertEquals(0, largeArray[rawSecret.length + 1]);
    assertEquals(0, largeArray[rawSecret.length + 2]);
  }

  @ParameterizedTest
  @MethodSource("params")
  public void secretInShortArray(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertNull(params.nativeAgreement.doPhase(params.pairs[1].getPublic(), true));
    final byte[] largeArray = new byte[params.rawSecrets[0][1].length + 3];

    assertThrows(
        ShortBufferException.class, () -> params.nativeAgreement.generateSecret(largeArray, 5));
  }

  @ParameterizedTest
  @MethodSource("params")
  public void rejectsInvalidKeys(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    for (final PublicKey key : params.invalidKeys) {
      assertThrows(InvalidKeyException.class, () -> params.nativeAgreement.doPhase(key, true));
    }
  }

  @ParameterizedTest
  @MethodSource("params")
  public void reInitRemovesSecret(TestParams params) throws GeneralSecurityException {
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    params.nativeAgreement.doPhase(params.pairs[0].getPublic(), true);
    params.nativeAgreement.init(params.pairs[0].getPrivate());
    assertThrows(
        IllegalStateException.class,
        "KeyAgreement has not been completed",
        () -> params.nativeAgreement.generateSecret());
  }

  @ParameterizedTest
  @MethodSource("params")
  public void miscErrorCases(TestParams params) throws GeneralSecurityException {
    // We need a copy to ensure we're on good clean state
    final KeyAgreement agree =
        KeyAgreement.getInstance(params.algorithm, params.nativeAgreement.getProvider());

    assertThrows(
        IllegalStateException.class,
        "KeyAgreement has not been initialized",
        () -> agree.doPhase(params.pairs[0].getPublic(), true));
    assertThrows(
        IllegalStateException.class,
        "KeyAgreement has not been initialized",
        agree::generateSecret);

    assertThrows(
        InvalidKeyException.class,
        () ->
            agree.init(
                new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.UTF_8), "AES")));

    assertThrows(InvalidKeyException.class, () -> agree.init(null));

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> agree.init(params.pairs[0].getPrivate(), new IvParameterSpec(new byte[0])));

    agree.init(params.pairs[0].getPrivate(), (AlgorithmParameterSpec) null);

    assertThrows(
        IllegalStateException.class,
        "Only single phase agreement is supported",
        () -> agree.doPhase(params.pairs[0].getPublic(), false));

    assertThrows(
        IllegalStateException.class, "KeyAgreement has not been completed", agree::generateSecret);

    assertThrows(
        InvalidKeyException.class,
        () ->
            agree.doPhase(
                new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.UTF_8), "AES"),
                true));
  }

  private void assertForAllPairs(
      TestParams params, TriConsumer<PublicKey, PrivateKey, byte[]> asserter) {
    for (int x = 0; x < params.pairs.length; x++) {
      for (int y = 0; y < params.pairs.length; y++) {
        asserter.accept(
            params.pairs[x].getPublic(), params.pairs[y].getPrivate(), params.rawSecrets[x][y]);
      }
    }
  }

  @FunctionalInterface
  private static interface TriConsumer<A, B, C> {
    public void inner(A a, B b, C c) throws Exception;

    public default void accept(A a, B b, C c) {
      try {
        inner(a, b, c);
      } catch (final RuntimeException ex) {
        throw ex;
      } catch (final Exception ex) {
        throw new RuntimeException(ex);
      }
    }
  }

  @SuppressWarnings("serial")
  public static class FakeEcPublicKey implements ECPublicKey {
    private final byte[] encoded;
    private final ECParameterSpec spec;
    private final ECPoint w;

    public FakeEcPublicKey(final byte[] encoded, final ECParameterSpec spec, final ECPoint w) {
      this.encoded = encoded;
      this.spec = spec;
      this.w = w;
    }

    @Override
    public String getAlgorithm() {
      return "EC";
    }

    @Override
    public byte[] getEncoded() {
      return encoded.clone();
    }

    @Override
    public String getFormat() {
      return "X.509";
    }

    @Override
    public ECParameterSpec getParams() {
      return spec;
    }

    @Override
    public ECPoint getW() {
      return w;
    }
  }
}
