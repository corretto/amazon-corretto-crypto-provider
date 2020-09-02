// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.NATIVE_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
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
    public static final String[][] KNOWN_CURVES = new String[][] {
            // Prime Curves
            new String[]{"secp112r1", "1.3.132.0.6"},
            new String[]{"secp112r2", "1.3.132.0.7"},
            new String[]{"secp128r1", "1.3.132.0.28"},
            new String[]{"secp128r2", "1.3.132.0.29"},
            new String[]{"secp160k1", "1.3.132.0.9"},
            new String[]{"secp160r1", "1.3.132.0.8"},
            new String[]{"secp160r2", "1.3.132.0.30"},
            new String[]{"secp192k1", "1.3.132.0.31"},
            // Not supported by Openssl
            new String[]{"secp192r1", "NIST P-192", "X9.62 prime192v1", /* "prime192v1", */ "1.2.840.10045.3.1.1"},
            new String[]{"secp224k1", "1.3.132.0.32"},
            new String[]{"secp224r1", "NIST P-224", "1.3.132.0.33"},
            new String[]{"secp256k1", "1.3.132.0.10"},
            // Not supported by Openssl
            new String[]{"secp256r1", "NIST P-256", "X9.62 prime256v1", /* "prime256v1", */ "1.2.840.10045.3.1.7"},
            new String[]{"secp384r1", "NIST P-384", "1.3.132.0.34"},
            new String[]{"secp521r1", "NIST P-521", "1.3.132.0.35"},
            // Binary Curves
            new String[]{"sect113r1", "1.3.132.0.4"},
            new String[]{"sect113r2", "1.3.132.0.5"},
            new String[]{"sect131r1", "1.3.132.0.22"},
            new String[]{"sect131r2", "1.3.132.0.23"},
            new String[]{"sect163k1", "NIST K-163", "1.3.132.0.1"},
            new String[]{"sect163r1", "1.3.132.0.2"},
            new String[]{"sect163r2", "NIST B-163", "1.3.132.0.15"},
            new String[]{"sect193r1", "1.3.132.0.24"},
            new String[]{"sect193r2", "1.3.132.0.25"},
            new String[]{"sect233k1", "NIST K-233", "1.3.132.0.26"},
            new String[]{"sect233r1", "NIST B-233", "1.3.132.0.27"},
            new String[]{"sect239k1", "1.3.132.0.3"},
            new String[]{"sect283k1", "NIST K-283", "1.3.132.0.16"},
            new String[]{"sect283r1", "NIST B-283", "1.3.132.0.17"},
            new String[]{"sect409k1", "NIST K-409", "1.3.132.0.36"},
            new String[]{"sect409r1", "NIST B-409", "1.3.132.0.37"},
            new String[]{"sect571k1", "NIST K-571", "1.3.132.0.38"},
            new String[]{"sect571r1", "NIST B-571", "1.3.132.0.39"},
            new String[]{"X9.62 c2tnb191v1", "1.2.840.10045.3.0.5"},
            new String[]{"X9.62 c2tnb191v2", "1.2.840.10045.3.0.6"},
            new String[]{"X9.62 c2tnb191v3", "1.2.840.10045.3.0.7"},
            new String[]{"X9.62 c2tnb239v1", "1.2.840.10045.3.0.11"},
            new String[]{"X9.62 c2tnb239v2", "1.2.840.10045.3.0.12"},
            new String[]{"X9.62 c2tnb239v3", "1.2.840.10045.3.0.13"},
            new String[]{"X9.62 c2tnb359v1", "1.2.840.10045.3.0.18"},
            new String[]{"X9.62 c2tnb431r1", "1.2.840.10045.3.0.20"},
            };
    public static final ECParameterSpec EXPLICIT_CURVE;
    private static final KeyFactory KEY_FACTORY;

    static {
        final BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16);
        final BigInteger b = new BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16);
        final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16);
        final BigInteger order = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16);
        final BigInteger gx = new BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16);
        final BigInteger gy = new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16);

        final ECFieldFp field = new ECFieldFp(p);
        final EllipticCurve curve = new EllipticCurve(field, a, b);
        final ECPoint g = new ECPoint(gx, gy);
        EXPLICIT_CURVE = new ECParameterSpec(curve, g, order, 1);
        try {
            KEY_FACTORY = KeyFactory.getInstance("EC");
        } catch (final NoSuchAlgorithmException ex) {
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
        // It is unclear if JUnit always properly releases references to classes and thus we may have memory leaks
        // if we do not properly null our references
        nativeGen = null;
        jceGen = null;
    }

    private static String[][] knownCurveParams() {
        return KNOWN_CURVES;
    }

    @ParameterizedTest
    @MethodSource("knownCurveParams")
    public void knownCurves(ArgumentsAccessor arguments) throws GeneralSecurityException {
        for (final Object name : arguments.toArray()) {
            ECGenParameterSpec spec = new ECGenParameterSpec((String) name);
            nativeGen.initialize(spec);
            KeyPair nativePair = nativeGen.generateKeyPair();
            jceGen.initialize(spec);
            KeyPair jcePair = jceGen.generateKeyPair();
            final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
            final ECParameterSpec nativeParams = ((ECPublicKey) nativePair.getPublic()).getParams();
            assertECEquals((String) name, jceParams, nativeParams);

            // Ensure we can construct the curve using raw numbers rather than the name
            nativeGen.initialize(jceParams);
            nativePair = nativeGen.generateKeyPair();
            assertECEquals(name + "-explicit", jceParams, nativeParams);

            final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(nativePair.getPublic().getEncoded());
            ASN1Encodable algorithmParameters = publicKeyInfo.getAlgorithm().getParameters();
            assertTrue(algorithmParameters instanceof ASN1ObjectIdentifier, "Public key uses named curve");

            // PKCS #8 = SEQ [ Integer, AlgorithmIdentifier, Octet String, ???]
            // AlgorithmIdentifier = SEQ [ OID, {OID | SEQ}]
            final ASN1Sequence p8 = ASN1Sequence.getInstance(nativePair.getPrivate().getEncoded());
            final ASN1Sequence algIdentifier = (ASN1Sequence) p8.getObjectAt(1);
            assertTrue(algIdentifier.getObjectAt(1) instanceof ASN1ObjectIdentifier, "Private key uses named curve");

            // Check encoding/decoding
            Key bouncedKey = KEY_FACTORY.generatePublic(new X509EncodedKeySpec(nativePair.getPublic().getEncoded()));
            assertEquals(nativePair.getPublic(), bouncedKey, "Public key survives encoding");
            bouncedKey = KEY_FACTORY.generatePrivate(new PKCS8EncodedKeySpec(nativePair.getPrivate().getEncoded()));
            assertEquals(nativePair.getPrivate(), bouncedKey, "Private key survives encoding");
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {192, 224, 256, 384, 521})
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
        TestUtil.assertThrows(InvalidParameterException.class,
                () -> nativeGen.initialize(13));
    }

    @Test
    public void explicitCurve() throws GeneralSecurityException {
        jceGen.initialize(EXPLICIT_CURVE);
        KeyPair jcePair = jceGen.generateKeyPair();
        nativeGen.initialize(EXPLICIT_CURVE);
        KeyPair nativePair = nativeGen.generateKeyPair();
        final ECParameterSpec jceParams = ((ECPublicKey) jcePair.getPublic()).getParams();
        assertECEquals("explicit", jceParams,
                ((ECPublicKey) nativePair.getPublic()).getParams());
    }

    @Test
    public void unknownCurve() throws GeneralSecurityException {
        final String curveName = "NonExistentFakeCurve";
        final String exMsg = "Unknown curve name: " + curveName;
        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        TestUtil.assertThrows(InvalidAlgorithmParameterException.class, exMsg, () -> {
            nativeGen.initialize(spec);
        });
    }

    @Test
    public void unknownCurveValidNid() throws GeneralSecurityException {
        final String curveName = "HMAC-MD5";
        final String exMsg = "Unknown curve name: " + curveName;
        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        TestUtil.assertThrows(InvalidAlgorithmParameterException.class, exMsg, () -> {
            nativeGen.initialize(spec);
        });
    }

    @Test
    public void validBinaryCurve() throws GeneralSecurityException {
        final String name = "sect113r1";
        ECGenParameterSpec spec = new ECGenParameterSpec(name);
        jceGen.initialize(spec);
        KeyPair jcePair = jceGen.generateKeyPair();
        nativeGen.initialize(spec);
        KeyPair nativePair = nativeGen.generateKeyPair();
        assertECEquals(name, ((ECPublicKey) jcePair.getPublic()).getParams(),
                ((ECPublicKey) nativePair.getPublic()).getParams());
    }

    @Test
    public void ecdsaValidation() throws GeneralSecurityException {
        final byte[] message = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        // We're purposefully using Java's ECDSA logic, since we trust it to be correct
        final Signature ecdsa = Signature.getInstance("NONEwithECDSA", "SunEC");
            for (final String[] names : KNOWN_CURVES) {
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
            final int curveIdx = rng.nextInt(KNOWN_CURVES.length);
            generators[x].initialize(new ECGenParameterSpec(KNOWN_CURVES[curveIdx][0]));
        }

        final List<TestThread> threads = new ArrayList<>();
        for (int x = 0; x < threadCount; x++) {
            threads.add(new TestThread("ECGenThread-" + x, iterations, generators[rng.nextInt(generatorCount)]));
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

    private static void assertECEquals(final String message, final ECParameterSpec expected,
            final ECParameterSpec actual) {
        assertEquals(expected.getCofactor(), actual.getCofactor(), message);
        assertEquals(expected.getOrder(), actual.getOrder(), message);
        assertEquals(expected.getGenerator(), actual.getGenerator(), message);
        assertEquals(expected.getCurve(), actual.getCurve(), message);
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
