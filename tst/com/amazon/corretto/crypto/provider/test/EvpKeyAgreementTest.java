// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
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
import java.util.Collection;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class EvpKeyAgreementTest {
    private static final BouncyCastleProvider BC_PROV = new BouncyCastleProvider();
    private static final int PAIR_COUNT = 25;
    private final String algorithm;
    @SuppressWarnings("unused")
    private final String displayName;
    @SuppressWarnings("unused")
    private KeyPairGenerator keyGen;
    // We test pairwise across lots of keypairs in an effort
    // to catch rarer edge-cases.
    private KeyPair[] pairs;
    private byte[][][] rawSecrets;
    private List<? extends PublicKey> invalidKeys;
    private final Provider nativeProvider;
    private final Provider jceProvider;
    private KeyAgreement nativeAgreement;
    private KeyAgreement jceAgreement;

    public EvpKeyAgreementTest(final String algorithm, final String displayName, final KeyPairGenerator keyGen,
            final Provider nativeProvider, final Provider jceProvider,
            final List<? extends PublicKey> invalidKeys) throws GeneralSecurityException {
        this.algorithm = algorithm;
        this.displayName = displayName;
        this.keyGen = keyGen;
        this.invalidKeys = invalidKeys;
        this.nativeProvider = nativeProvider;
        this.jceProvider = jceProvider;
    }

    @Parameters(name = "{1}")
    public static Collection<Object[]> data() throws Exception {
        final List<Object[]> params = new ArrayList<>();

        params.add(buildEcdhParameters(new ECGenParameterSpec("secp112r1"), "secp112r1"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-224"), "NIST P-224"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-384"), "NIST P-384"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("NIST P-521"), "NIST P-521"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("sect113r1"), "sect113r1"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("sect163k1"), "sect163k1"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("sect283k1"), "sect283k1"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("sect571r1"), "sect571r1"));
        params.add(buildEcdhParameters(new ECGenParameterSpec("X9.62 c2tnb239v3"), "X9.62 c2tnb239v3"));
        params.add(buildEcdhParameters(EcGenTest.EXPLICIT_CURVE, "Explicit Curve"));

        params.add(buildDhParameters(512));
        params.add(buildDhParameters(1024));
        params.add(buildDhParameters(2048));
        return params;
    }

    @Before
    public void setup() throws GeneralSecurityException {
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

    @After
    public void teardown() {
        // It is unclear if JUnit always properly releases references to classes and thus we may have memory leaks
        // if we do not properly null our references
        nativeAgreement = null;
        jceAgreement = null;
        pairs = null;
        rawSecrets = null;
        invalidKeys = null;
        keyGen = null;
    }

    private static Object[] buildDhParameters(final int keySize) throws GeneralSecurityException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        generator.initialize(keySize);
        final DHPublicKey pubKey = (DHPublicKey) generator.generateKeyPair().getPublic();
        final List<DHPublicKey> badKeys = new ArrayList<>();
        badKeys.addAll(buildWeakDhKeys(pubKey));
        badKeys.add(buildDhKeyWithRandomParams(keySize));
        return new Object[] {
                "DH",
                "DH(" + keySize + ")",
                generator,
                AmazonCorrettoCryptoProvider.INSTANCE,
                BC_PROV,
                badKeys
            };

    }

    private static Object[] buildEcdhParameters(final AlgorithmParameterSpec genSpec, final String name)
            throws GeneralSecurityException, IOException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", AmazonCorrettoCryptoProvider.INSTANCE);
        generator.initialize(genSpec);
        final KeyPair pair = generator.generateKeyPair();
        final ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
        return new Object[] {
                "ECDH",
                "ECDH(" + name + ")",
                generator,
                AmazonCorrettoCryptoProvider.INSTANCE,
                BC_PROV,
                Arrays.asList(
                        buildKeyAtInfinity(pubKey),
                        buildKeyOffCurve(pubKey),
                        buildKeyOnWrongCurve(pubKey),
                        buildKeyOnWrongField(pubKey))
            };
    }

    private static List<DHPublicKey> buildWeakDhKeys(final DHPublicKey goodKey) throws GeneralSecurityException {
        final KeyFactory factory = KeyFactory.getInstance("DH");
        final List<DHPublicKey> badKeys = new ArrayList<>();
        final BigInteger p = goodKey.getParams().getP();
        final BigInteger g = goodKey.getParams().getG();
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(BigInteger.ZERO, p, g)));
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(BigInteger.ONE, p, g)));
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(p.subtract(BigInteger.ONE), p, g)));
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(p, p, g)));
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(p.add(BigInteger.ONE), p, g)));
        badKeys.add((DHPublicKey) factory.generatePublic(new DHPublicKeySpec(BigInteger.ONE.negate(), p, g)));
        return badKeys;
    }

    static DHPublicKey buildDhKeyWithRandomParams(final int keySize) throws GeneralSecurityException {
        final AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(keySize);
        final AlgorithmParameters params = paramGen.generateParameters();
        final DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("DH");
        kg.initialize(spec);
        return (DHPublicKey) kg.generateKeyPair().getPublic();
    }

    static ECPublicKey buildKeyOffCurve(final ECPublicKey goodKey) throws GeneralSecurityException {
        final KeyFactory factory = KeyFactory.getInstance("EC");
        final ECPoint w = new ECPoint(goodKey.getW().getAffineX().add(BigInteger.ONE), goodKey.getW().getAffineY());
        final ECPublicKey badKey = (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(w, goodKey.getParams()));
        return badKey;
    }

    static ECPublicKey buildKeyAtInfinity(final ECPublicKey goodKey) throws IOException {
        // We can't build this normally because Java protects us from these bad keys
        final byte[] goodDer = goodKey.getEncoded();
        ASN1Sequence seq = ASN1Sequence.getInstance(goodDer);
        // This should consist of two elements, algorithm and the actual key
        assertEquals("Unexpected ASN.1 encoding", 2, seq.size());
        // The key itself is just a byte encoding of the point
        DERBitString point = (DERBitString) seq.getObjectAt(1);
        point = new DERBitString(new byte[1]); // a one byte zero array is the point at infinity
        seq = new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0), point });
        return new FakeEcPublicKey(seq.getEncoded("DER"), goodKey.getParams(), ECPoint.POINT_INFINITY);
    }

    static ECPublicKey buildKeyOnWrongCurve(final ECPublicKey goodKey) throws GeneralSecurityException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final EllipticCurve curve = goodKey.getParams().getCurve();
        if (curve.getField() instanceof ECFieldFp) {
            // This is a prime curve
            generator.initialize(new ECGenParameterSpec("NIST P-384"));
            final ECPublicKey pub1 = (ECPublicKey) generator.generateKeyPair().getPublic();
            generator.initialize(new ECGenParameterSpec("NIST P-224"));
            final ECPublicKey pub2 = (ECPublicKey) generator.generateKeyPair().getPublic();

            if (curve.getField().getFieldSize() == pub1.getParams().getCurve().getField().getFieldSize()) {
                return pub2;
            } else {
                return pub1;
            }
        } else {
            generator.initialize(new ECGenParameterSpec("sect163k1"));
            final ECPublicKey pub1 = (ECPublicKey) generator.generateKeyPair().getPublic();
            generator.initialize(new ECGenParameterSpec("sect283k1"));
            final ECPublicKey pub2 = (ECPublicKey) generator.generateKeyPair().getPublic();

            if (curve.getField().getFieldSize() == pub1.getParams().getCurve().getField().getFieldSize()) {
                return pub2;
            } else {
                return pub1;
            }
        }
    }

    public static ECPublicKey buildKeyOnWrongField(final ECPublicKey goodKey) throws GeneralSecurityException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final EllipticCurve curve = goodKey.getParams().getCurve();
        if (curve.getField() instanceof ECFieldFp) {
            generator.initialize(new ECGenParameterSpec("sect163k1"));
            return (ECPublicKey) generator.generateKeyPair().getPublic();
        } else {
            generator.initialize(new ECGenParameterSpec("NIST P-384"));
            return (ECPublicKey) generator.generateKeyPair().getPublic();
        }
    }

    @Test
    public void jceCompatability() throws GeneralSecurityException {
        assertForAllPairs((pub, priv, expected) -> {
            nativeAgreement.init(priv);
            assertNull(nativeAgreement.doPhase(pub, true));
            assertArrayEquals(expected, nativeAgreement.generateSecret());
        });
    }

    @Test
    public void tlsMasterSecret() throws GeneralSecurityException {
        // For TLS suppport we /must/ support this algorithm
        assertForAllPairs((pub, priv, ignored) -> {
            nativeAgreement.init(priv);
            assertNull(nativeAgreement.doPhase(pub, true));
            final SecretKey nativeKey = nativeAgreement.generateSecret("TlsPremasterSecret");

            jceAgreement.init(priv);
            jceAgreement.doPhase(pub, true);
            final SecretKey jceKey = jceAgreement.generateSecret("TlsPremasterSecret");

            assertEquals(jceKey.getAlgorithm(), nativeKey.getAlgorithm());
            assertEquals(jceKey.getFormat(), nativeKey.getFormat());
            assertArrayEquals(jceKey.getEncoded(), nativeKey.getEncoded());
        });
    }

    @Test
    public void aesKeys() throws GeneralSecurityException {
        final byte[] rawSecret = rawSecrets[0][1];
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));

        final int expectedKeyLength = Math.min(32, (rawSecret.length / 8) * 8);
        assumeTrue(expectedKeyLength > 16);
        final SecretKey aesKey = nativeAgreement.generateSecret("AES");
        assertEquals("AES", aesKey.getAlgorithm());
        assertEquals("RAW", aesKey.getFormat());
        assertArrayEquals(Arrays.copyOf(rawSecret, expectedKeyLength), aesKey.getEncoded());
    }

    @Test
    public void aesKeysExplicitSize() throws GeneralSecurityException {
        // 0, 20, and 4096 to trigger error cases
        final int[] keySizes = new int[] { 0, 16, 20, 24, 32, 4096 };
        for (final int size : keySizes) {
            final byte[] rawSecret = rawSecrets[0][1];
            nativeAgreement.init(pairs[0].getPrivate());
            assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
            final String secretAlg = "AES[" + size + "]";
            if (size > 0 && size <= rawSecret.length && size != 20) {
                final SecretKey aesKey = nativeAgreement.generateSecret(secretAlg);
                assertEquals("AES", aesKey.getAlgorithm());
                assertEquals("RAW", aesKey.getFormat());
                assertArrayEquals(Arrays.copyOf(rawSecret, size), aesKey.getEncoded());
            } else {
                assertThrows(InvalidKeyException.class, () -> nativeAgreement.generateSecret(secretAlg));
            }
        }
    }

    @Test
    public void fakeAlgorithm() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
        assertThrows(InvalidKeyException.class, () -> nativeAgreement.generateSecret("FAKE_ALG"));
    }

    @Test
    public void fakeAlgorithmExplicitSize() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
        assertThrows(InvalidKeyException.class, () -> nativeAgreement.generateSecret("FAKE_ALG[8]"));
    }

    @Test
    public void fakeWeirdAlgorithmName() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
        assertThrows(InvalidKeyException.class, () -> nativeAgreement.generateSecret(" #$*(& DO  3VR89"));
    }

    @Test
    public void secretInExistingArray() throws GeneralSecurityException {
        final byte[] rawSecret = rawSecrets[0][1];
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
        final byte[] largeArray = new byte[rawSecret.length + 3];
        nativeAgreement.generateSecret(largeArray, 1);

        assertArrayEquals(rawSecret, Arrays.copyOfRange(largeArray, 1, 1 + rawSecret.length));
        assertEquals(0, largeArray[0]);
        assertEquals(0, largeArray[rawSecret.length + 1]);
        assertEquals(0, largeArray[rawSecret.length + 2]);
    }

    @Test
    public void secretInShortArray() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        assertNull(nativeAgreement.doPhase(pairs[1].getPublic(), true));
        final byte[] largeArray = new byte[rawSecrets[0][1].length + 3];

        assertThrows(ShortBufferException.class, () -> nativeAgreement.generateSecret(largeArray, 5));
    }

    @Test
    public void rejectsInvalidKeys() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        for (final PublicKey key : invalidKeys) {
            assertThrows(InvalidKeyException.class, () -> nativeAgreement.doPhase(key, true));
        }

    }

    @Test
    public void reInitRemovesSecret() throws GeneralSecurityException {
        nativeAgreement.init(pairs[0].getPrivate());
        nativeAgreement.doPhase(pairs[0].getPublic(), true);
        nativeAgreement.init(pairs[0].getPrivate());
        assertThrows(IllegalStateException.class, "KeyAgreement has not been completed",
          () -> nativeAgreement.generateSecret());
    }

    @Test
    public void miscErrorCases() throws GeneralSecurityException {
        // We need a copy to ensure we're on good clean state
        final KeyAgreement agree = KeyAgreement.getInstance(algorithm, nativeAgreement.getProvider());

        assertThrows(IllegalStateException.class, "KeyAgreement has not been initialized",
                () -> agree.doPhase(pairs[0].getPublic(), true));
        assertThrows(IllegalStateException.class, "KeyAgreement has not been initialized", () -> agree.generateSecret());

        assertThrows(InvalidKeyException.class,
                () -> agree.init(new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.UTF_8), "AES")));

        assertThrows(InvalidKeyException.class, () -> agree.init(null));

        assertThrows(InvalidAlgorithmParameterException.class,
                () -> agree.init(pairs[0].getPrivate(), new IvParameterSpec(new byte[0])));

        agree.init(pairs[0].getPrivate(), (AlgorithmParameterSpec) null);

        // This test doesn't apply to DH
        if (!algorithm.equals("DH")) {
            assertThrows(IllegalStateException.class, "Only single phase agreement is supported",
                    () -> agree.doPhase(pairs[0].getPublic(), false));
        }
        assertThrows(IllegalStateException.class, "KeyAgreement has not been completed", () -> agree.generateSecret());

        assertThrows(InvalidKeyException.class,
                () -> agree.doPhase(new SecretKeySpec("YellowSubmarine".getBytes(StandardCharsets.UTF_8), "AES"), true));

    }

    private void assertForAllPairs(TriConsumer<PublicKey, PrivateKey, byte[]> asserter) {
        for (int x = 0; x < pairs.length; x++) {
            for (int y = 0; y < pairs.length; y++) {
                asserter.accept(pairs[x].getPublic(), pairs[y].getPrivate(), rawSecrets[x][y]);
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
