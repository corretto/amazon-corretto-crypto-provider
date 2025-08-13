// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class EcGenTest {
  public static final ECParameterSpec EXPLICIT_CURVE;
  private static final KeyFactory KEY_FACTORY;
  // We use some methods from it in our tests
  private static final Class<?> EC_UTILS_CLASS;

  static {
    final BigInteger a =
        new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            16);
    final BigInteger b =
        new BigInteger(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            16);
    final BigInteger p =
        new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            16);
    final BigInteger order =
        new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            16);
    final BigInteger gx =
        new BigInteger(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            16);
    final BigInteger gy =
        new BigInteger(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            16);

    final ECFieldFp field = new ECFieldFp(p);
    final EllipticCurve curve = new EllipticCurve(field, a, b);
    final ECPoint g = new ECPoint(gx, gy);
    EXPLICIT_CURVE = new ECParameterSpec(curve, g, order, 1);
    try {
      KEY_FACTORY = KeyFactory.getInstance("EC", NATIVE_PROVIDER);
      EC_UTILS_CLASS = Class.forName(TestUtil.NATIVE_PROVIDER_PACKAGE + ".EcUtils");
    } catch (final Exception ex) {
      throw new AssertionError(ex);
    }
  }

  private KeyPairGenerator nativeGen;
  private KeyPairGenerator jceGen;

  @BeforeEach
  public void setup() throws GeneralSecurityException {
    nativeGen = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
    jceGen = KeyPairGenerator.getInstance("EC", "SunEC");
  }

  @AfterEach
  public void teardown() {
    // It is unclear if JUnit always properly releases references to classes and thus we may have
    // memory leaks
    // if we do not properly null our references
    nativeGen = null;
    jceGen = null;
  }

  private static String[][] legacyCurveParams() {
    return TestUtil.LEGACY_CURVES;
  }

  @ParameterizedTest
  @EnabledForJreRange(min = JRE.JAVA_8, max = JRE.JAVA_14)
  @MethodSource("legacyCurveParams")
  public void legacyCurves(ArgumentsAccessor arguments) throws GeneralSecurityException {
    for (final Object name : arguments.toArray()) {
      testCurveByName((String) name);
    }
  }

  private static String[][] knownCurveParams() {
    return TestUtil.KNOWN_CURVES;
  }

  @ParameterizedTest
  @MethodSource("knownCurveParams")
  public void knownCurves(ArgumentsAccessor arguments) throws Exception {
    for (final Object name : arguments.toArray()) {
      testCurveByName((String) name);
    }
  }

  private void testCurveByName(String name) throws GeneralSecurityException {
    ECGenParameterSpec spec = new ECGenParameterSpec(name);
    nativeGen.initialize(spec);
    KeyPair nativePair = nativeGen.generateKeyPair();
    jceGen.initialize(spec);
    KeyPair jcePair = jceGen.generateKeyPair();
    final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
    final ECParameterSpec nativeParams = ((ECPublicKey) nativePair.getPublic()).getParams();
    assertECEquals(name, jceParams, nativeParams);

    // Ensure we can construct the curve using raw numbers rather than the name
    nativeGen.initialize(jceParams);
    nativePair = nativeGen.generateKeyPair();
    assertECEquals(name + "-explicit", jceParams, nativeParams);

    final SubjectPublicKeyInfo publicKeyInfo =
        SubjectPublicKeyInfo.getInstance(nativePair.getPublic().getEncoded());
    ASN1Encodable algorithmParameters = publicKeyInfo.getAlgorithm().getParameters();
    assertTrue(algorithmParameters instanceof ASN1ObjectIdentifier, "Public key uses named curve");

    // PKCS #8 = SEQ [ Integer, AlgorithmIdentifier, Octet String, ???]
    // AlgorithmIdentifier = SEQ [ OID, {OID | SEQ}]
    final ASN1Sequence p8 = ASN1Sequence.getInstance(nativePair.getPrivate().getEncoded());
    final ASN1Sequence algIdentifier = (ASN1Sequence) p8.getObjectAt(1);
    assertTrue(
        algIdentifier.getObjectAt(1) instanceof ASN1ObjectIdentifier,
        "Private key uses named curve");

    // Check encoding/decoding
    Key bouncedKey =
        KEY_FACTORY.generatePublic(new X509EncodedKeySpec(nativePair.getPublic().getEncoded()));
    assertEquals(nativePair.getPublic(), bouncedKey, "Public key survives encoding");
    bouncedKey =
        KEY_FACTORY.generatePrivate(new PKCS8EncodedKeySpec(nativePair.getPrivate().getEncoded()));
    assertEquals(nativePair.getPrivate(), bouncedKey, "Private key survives encoding");
  }

  @ParameterizedTest
  @EnabledForJreRange(min = JRE.JAVA_8, max = JRE.JAVA_14)
  @ValueSource(ints = {224})
  public void legacyKnownSizes(int keysize) throws GeneralSecurityException {
    TestUtil.assumeMinimumVersion("1.2.0", nativeGen.getProvider());
    nativeGen.initialize(keysize);
    jceGen.initialize(keysize);

    final KeyPair nativePair = nativeGen.generateKeyPair();
    final KeyPair jcePair = jceGen.generateKeyPair();

    final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
    final ECParameterSpec nativeParams = ((ECPublicKey) nativePair.getPublic()).getParams();
    assertECEquals(Integer.toString(keysize), jceParams, nativeParams);
  }

  @ParameterizedTest
  @ValueSource(ints = {256, 384, 521})
  public void knownSizes(int keysize) throws GeneralSecurityException {
    TestUtil.assumeMinimumVersion("1.2.0", nativeGen.getProvider());
    nativeGen.initialize(keysize);
    jceGen.initialize(keysize);

    final KeyPair nativePair = nativeGen.generateKeyPair();
    final KeyPair jcePair = jceGen.generateKeyPair();

    final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
    final ECParameterSpec nativeParams = ((ECPublicKey) nativePair.getPublic()).getParams();
    assertECEquals(Integer.toString(keysize), jceParams, nativeParams);
  }

  @Test
  public void explicitSizesOnly() throws GeneralSecurityException {
    TestUtil.assumeMinimumVersion("1.6.0", nativeGen.getProvider());
    TestUtil.assertThrows(InvalidParameterException.class, () -> nativeGen.initialize(128));
  }

  @Test
  public void unknownSize() throws GeneralSecurityException {
    TestUtil.assertThrows(InvalidParameterException.class, () -> nativeGen.initialize(13));
  }

  @Test
  public void explicitCurve() throws GeneralSecurityException {
    jceGen.initialize(EXPLICIT_CURVE);
    KeyPair jcePair = jceGen.generateKeyPair();
    nativeGen.initialize(EXPLICIT_CURVE);
    KeyPair nativePair = nativeGen.generateKeyPair();
    final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
    assertECEquals("explicit", jceParams, ((ECPublicKey) nativePair.getPublic()).getParams());
  }

  @Test
  public void unknownCurve() throws GeneralSecurityException {
    final String curveName = "NonExistentFakeCurve";
    final String exMsg = "Unknown curve name: " + curveName;
    ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
    TestUtil.assertThrows(
        InvalidAlgorithmParameterException.class,
        exMsg,
        () -> {
          nativeGen.initialize(spec);
        });
  }

  @Test
  public void unknownCurveValidNid() throws GeneralSecurityException {
    final String curveName = "HMAC-MD5";
    final String exMsg = "Unknown curve name: " + curveName;
    ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
    TestUtil.assertThrows(
        InvalidAlgorithmParameterException.class,
        exMsg,
        () -> {
          nativeGen.initialize(spec);
        });
  }

  @Test
  public void ecdsaValidation() throws GeneralSecurityException {
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // We're purposefully using Java's ECDSA logic, since we trust it to be correct
    final Signature ecdsa = Signature.getInstance("NONEwithECDSA", "SunEC");
    for (final String[] names : TestUtil.KNOWN_CURVES) {
      for (final String name : names) {
        nativeGen.initialize(new ECGenParameterSpec(name));
        final KeyPair keyPair = nativeGen.generateKeyPair();

        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update(message);
        final byte[] signature = ecdsa.sign();

        ecdsa.initVerify(keyPair.getPublic());
        ecdsa.update(message);
        assertTrue(ecdsa.verify(signature), name);
      }
    }
  }

  @Test
  @EnabledForJreRange(min = JRE.JAVA_8, max = JRE.JAVA_14)
  public void LegacyEcdsaValidation() throws GeneralSecurityException {
    final byte[] message = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // We're purposefully using Java's ECDSA logic, since we trust it to be correct
    final Signature ecdsa = Signature.getInstance("NONEwithECDSA", "SunEC");
    for (final String[] names : TestUtil.LEGACY_CURVES) {
      for (final String name : names) {
        nativeGen.initialize(new ECGenParameterSpec(name));
        final KeyPair keyPair = nativeGen.generateKeyPair();

        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update(message);
        final byte[] signature = ecdsa.sign();

        ecdsa.initVerify(keyPair.getPublic());
        ecdsa.update(message);
        assertTrue(ecdsa.verify(signature), name);
      }
    }
  }

  @Test
  public void defaultParams() throws GeneralSecurityException {
    nativeGen.generateKeyPair();
  }

  @Test
  public void separateDestruction() throws Exception {
    final KeyPair keyPair = nativeGen.generateKeyPair();
    RsaGenTest.testSeparateDestruction(keyPair);
  }

  @Test
  public void threadStorm() throws Throwable {
    final byte[] rngSeed = TestUtil.getRandomBytes(20);
    System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
    final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
    rng.setSeed(rngSeed);
    final int generatorCount = 8;
    final int iterations = 500;
    final int threadCount = 48;

    final KeyPairGenerator[] generators = new KeyPairGenerator[generatorCount];
    for (int x = 0; x < generatorCount; x++) {
      generators[x] = KeyPairGenerator.getInstance("EC", NATIVE_PROVIDER);
      final int curveIdx = rng.nextInt(TestUtil.KNOWN_CURVES.length);
      generators[x].initialize(new ECGenParameterSpec(TestUtil.KNOWN_CURVES[curveIdx][0]));
    }

    final List<TestThread> threads = new ArrayList<>();
    for (int x = 0; x < threadCount; x++) {
      threads.add(
          new TestThread("ECGenThread-" + x, iterations, generators[rng.nextInt(generatorCount)]));
    }

    // Start the threads
    for (final TestThread t : threads) {
      t.start();
    }

    // Wait and collect the results
    final List<Throwable> results = new ArrayList<>();
    for (final TestThread t : threads) {
      t.join();
      if (t.result != null) {
        results.add(t.result);
      }
    }
    if (!results.isEmpty()) {
      final AssertionError ex = new AssertionError("Throwable while testing threads");
      for (Throwable t : results) {
        ex.addSuppressed(t);
      }
      throw ex;
    }
  }

  public static void assertECEquals(
      final String message, final ECPrivateKey expected, final ECPrivateKey actual) {
    final boolean expectEncodingCompat = TestUtil.JAVA_VERSION != 10;
    if (expectEncodingCompat) {
      assertArrayEquals(expected.getEncoded(), actual.getEncoded(), message);
    }
    assertEquals(expected.getAlgorithm(), actual.getAlgorithm(), message);
    assertEquals(expected.getFormat(), actual.getFormat(), message);
    assertEquals(expected.getS(), actual.getS(), message);
    assertECEquals(message, expected.getParams(), actual.getParams());
  }

  public static void assertECEquals(
      final String message, final ECPublicKey expected, final ECPublicKey actual) {
    assertEquals(expected.getAlgorithm(), actual.getAlgorithm(), message);
    assertEquals(expected.getFormat(), actual.getFormat(), message);
    assertArrayEquals(expected.getEncoded(), actual.getEncoded(), message);
    assertEquals(expected.getW(), actual.getW(), message);
    assertECEquals(message, expected.getParams(), actual.getParams());
  }

  public static void assertECEquals(
      final String message, final ECParameterSpec expected, final ECParameterSpec actual) {
    boolean result = false;
    try {
      result = TestUtil.sneakyInvoke(EC_UTILS_CLASS, "ecParameterSpecsAreEqual", expected, actual);
    } catch (final Throwable t) {
      throw new AssertionError(message, t);
    }
    assertTrue(result, message);
  }

  public static void assertECEquals(
      final String message, final ECGenParameterSpec expected, final ECGenParameterSpec actual) {
    assertEquals(expected.getName(), actual.getName(), message);
  }

  private static class TestThread extends Thread {
    private final int iterations;
    private final KeyPairGenerator kg;
    private Throwable result = null;

    public TestThread(final String name, final int iterations, final KeyPairGenerator kg) {
      super(name);
      this.iterations = iterations;
      this.kg = kg;
    }

    @Override
    public void run() {
      for (int x = 0; x < iterations; x++) {
        try {
          kg.generateKeyPair();
        } catch (final Throwable t) {
          result = t;
          return;
        }
      }
    }
  }
}
